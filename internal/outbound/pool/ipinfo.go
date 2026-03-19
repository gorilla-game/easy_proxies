package pool

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"easy_proxies/internal/monitor"

	utls "github.com/metacubex/utls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	ipInfoHost        = "my.123169.xyz"
	ipInfoPath        = "/v1/info"
	ipInfoMinInterval = 10 * time.Minute
	ipInfoTimeout     = 8 * time.Second
	dklyHost          = "ipinfo.dkly.net"
	dklyPath          = "/api/"
	dklyKey           = "a3b3be25941f14415ba93648ea46308cd5f9d6d7c256dc4753a351eaf8cc9b0e"
	dklyTimeout       = 6 * time.Second
	ping0Host         = "ping0.cc"
	ping0Path         = "/"
	ping0Timeout      = 4 * time.Second
	iplarkHost        = "iplark.com"
	iplarkPath        = "/"
	iplarkTimeout     = 4 * time.Second
	scamHost          = "scamalytics.com"
	scamTimeout       = 4 * time.Second
	scamSuccessTTL    = 1 * time.Hour
	scamFailureTTL    = 24 * time.Hour
	chromeUserAgent   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

var (
	ping0UsecountAttr = regexp.MustCompile(`usecount="([^"]+)"`)
	ping0UsecountBar  = regexp.MustCompile(`class="usecountbar"[^>]*>\s*([^<]+)\s*</div>`)
	ping0NodesInit    = regexp.MustCompile(`window\.nodes\s*=\s*\[\]`)
	ping0NodesPush    = regexp.MustCompile(`window\.nodes\.push\(`)
	ping0IPJS         = regexp.MustCompile(`window\.ip\s*=\s*'([^']+)'`)
	ping0IPHref       = regexp.MustCompile(`href="[^"]*?/ping/([0-9.]+)"`)
	ping0Type         = regexp.MustCompile(`(?s)<div class="line line-iptype">.*?<span class="label[^>]*>(.*?)</span>`)
	ping0Native       = regexp.MustCompile(`(?s)<div class="line line-nativeip">.*?<span class="label[^>]*>(.*?)</span>`)
	ping0Score        = regexp.MustCompile(`class="riskitem riskcurrent"[^>]*><span class="value">(\d+)%</span>`)
	ping0HTMLTag      = regexp.MustCompile(`<[^>]+>`)
	iplarkASLine      = regexp.MustCompile(`(?i)\bAS(\d+)\b`)
	scamScore         = regexp.MustCompile(`Fraud Score:\s*([0-9]{1,3})`)
)

type scamScoreCache struct {
	ip          string
	score       string
	lastSuccess time.Time
}

func (p *poolOutbound) cachedScamScore(tag, ip string, successTTL time.Duration) (string, bool) {
	if tag == "" || ip == "" {
		return "", false
	}
	p.scamCacheMu.Lock()
	entry, ok := p.scamCache[tag]
	p.scamCacheMu.Unlock()
	if !ok || entry == nil || entry.ip != ip || strings.TrimSpace(entry.score) == "" {
		return "", false
	}
	if entry.lastSuccess.IsZero() || time.Since(entry.lastSuccess) > successTTL {
		return "", false
	}
	return entry.score, true
}

func (p *poolOutbound) scamCacheFallback(tag, ip string) (string, time.Time, bool) {
	if tag == "" || ip == "" {
		return "", time.Time{}, false
	}
	p.scamCacheMu.Lock()
	entry, ok := p.scamCache[tag]
	p.scamCacheMu.Unlock()
	if !ok || entry == nil || entry.ip != ip || strings.TrimSpace(entry.score) == "" {
		return "", time.Time{}, false
	}
	return entry.score, entry.lastSuccess, !entry.lastSuccess.IsZero()
}

func (p *poolOutbound) storeScamScore(tag, ip, score string) {
	if tag == "" || ip == "" || strings.TrimSpace(score) == "" {
		return
	}
	now := time.Now()
	p.scamCacheMu.Lock()
	p.scamCache[tag] = &scamScoreCache{
		ip:          ip,
		score:       strings.TrimSpace(score),
		lastSuccess: now,
	}
	p.scamCacheMu.Unlock()
}

type ippureInfoResponse struct {
	IP             string      `json:"ip"`
	ASN            json.Number `json:"asn"`
	ASOrganization string      `json:"asOrganization"`
	Country        string      `json:"country"`
	CountryCode    string      `json:"countryCode"`
	City           string      `json:"city"`
	FraudScore     json.Number `json:"fraudScore"`
	BotScore       json.Number `json:"botScore"`
	HumanBotRatio  json.Number `json:"humanBotRatio"`
	IsResidential  bool        `json:"isResidential"`
	IsBroadcast    bool        `json:"isBroadcast"`
}

type dklySecurityResponse struct {
	IsAbuser        bool `json:"is_abuser"`
	IsAttacker      bool `json:"is_attacker"`
	IsBogon         bool `json:"is_bogon"`
	IsCloudProvider bool `json:"is_cloud_provider"`
	IsProxy         bool `json:"is_proxy"`
	IsRelay         bool `json:"is_relay"`
	IsTor           bool `json:"is_tor"`
	IsTorExit       bool `json:"is_tor_exit"`
	IsVPN           bool `json:"is_vpn"`
	IsAnonymous     bool `json:"is_anonymous"`
	IsThreat        bool `json:"is_threat"`
}

type dklyInfoResponse struct {
	IP         string `json:"ip"`
	Connection struct {
		ASN          json.Number `json:"asn"`
		Organization string      `json:"organization"`
		Type         string      `json:"type"`
	} `json:"connection"`
	Company struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"company"`
	Location struct {
		Country struct {
			Code string `json:"code"`
			Name string `json:"name"`
		} `json:"country"`
		Region struct {
			Name string `json:"name"`
		} `json:"region"`
		City string `json:"city"`
	} `json:"location"`
	Security dklySecurityResponse `json:"security"`
}

func joinLocation(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			continue
		}
		out = append(out, strings.TrimSpace(part))
	}
	return strings.Join(out, " ")
}

func setBrowserHeaders(req *http.Request, accept string) {
	if req == nil {
		return
	}
	req.Header.Set("User-Agent", chromeUserAgent)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Connection", "close")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
}

func (p *poolOutbound) dialTLSConn(ctx context.Context, member *memberState, host string, port uint16, timeout time.Duration, browserLike bool) (net.Conn, error) {
	if member == nil || member.outbound == nil {
		return nil, fmt.Errorf("missing outbound")
	}

	target := M.ParseSocksaddrHostPort(host, port)
	conn, err := member.outbound.DialContext(ctx, N.NetworkTCP, target)
	if err != nil {
		return nil, err
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if !browserLike {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: host})
		if err := tlsConn.Handshake(); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		return tlsConn, nil
	}

	utlsConn := utls.UClient(conn, &utls.Config{
		ServerName: host,
		NextProtos: []string{"http/1.1"},
	}, utls.HelloChrome_Auto)
	if err := utlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}
	return utlsConn, nil
}

func (p *poolOutbound) doHTTPSRequest(ctx context.Context, member *memberState, host string, path string, timeout time.Duration, browserLike bool, accept string) (*http.Response, error) {
	conn, err := p.dialTLSConn(ctx, member, host, 443, timeout, browserLike)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	setBrowserHeaders(req, accept)

	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return resp, nil
}

func (p *poolOutbound) maybeRefreshIPInfo(member *memberState) {
	if member == nil || member.entry == nil {
		return
	}
	if !member.entry.IPInfoStale(ipInfoMinInterval) {
		return
	}

	ctx, cancel := context.WithTimeout(p.ctx, ipInfoTimeout)
	go func() {
		defer cancel()
		info, err := p.fetchIPInfo(ctx, member)
		if err != nil {
			if p.logger != nil {
				p.logger.Warn("ip info check failed for ", member.tag, ": ", err)
			}
			return
		}
		member.entry.SetIPInfo(*info)
	}()
}

func (p *poolOutbound) fetchIPInfo(ctx context.Context, member *memberState) (*monitor.IPInfo, error) {
	source := strings.ToLower(strings.TrimSpace(p.options.IPInfoSource))
	if source == "" {
		source = "ping0"
	}
	switch source {
	case "ping0", "ippure", "iplark", "dkly":
	default:
		source = "ping0"
	}

	type ipInfoResult struct {
		info *monitor.IPInfo
		err  error
	}

	var wg sync.WaitGroup
	wg.Add(4)

	ping0Ch := make(chan ipInfoResult, 1)
	ippureCh := make(chan ipInfoResult, 1)
	iplarkCh := make(chan ipInfoResult, 1)
	dklyCh := make(chan ipInfoResult, 1)

	go func() {
		defer wg.Done()
		info, err := p.fetchPing0Info(ctx, member)
		ping0Ch <- ipInfoResult{info: info, err: err}
	}()

	go func() {
		defer wg.Done()
		info, err := p.fetchIppureInfo(ctx, member, true)
		ippureCh <- ipInfoResult{info: info, err: err}
	}()

	go func() {
		defer wg.Done()
		info, err := p.fetchIplarkInfo(ctx, member)
		iplarkCh <- ipInfoResult{info: info, err: err}
	}()

	go func() {
		defer wg.Done()
		info, err := p.fetchDKLYInfo(ctx, member)
		dklyCh <- ipInfoResult{info: info, err: err}
	}()

	wg.Wait()
	ping0Result := <-ping0Ch
	ippureResult := <-ippureCh
	iplarkResult := <-iplarkCh
	dklyResult := <-dklyCh

	var primary ipInfoResult
	fallbacks := make([]ipInfoResult, 0, 3)
	switch source {
	case "ippure":
		primary = ippureResult
		fallbacks = append(fallbacks, ping0Result, iplarkResult, dklyResult)
	case "iplark":
		primary = iplarkResult
		fallbacks = append(fallbacks, ping0Result, ippureResult, dklyResult)
	case "dkly":
		primary = dklyResult
		fallbacks = append(fallbacks, ping0Result, ippureResult, iplarkResult)
	default:
		primary = ping0Result
		fallbacks = append(fallbacks, ippureResult, iplarkResult, dklyResult)
	}

	if primary.info == nil {
		for _, candidate := range fallbacks {
			if candidate.info != nil {
				primary = candidate
				break
			}
		}
	}

	if primary.info == nil {
		var errs []string
		if ping0Result.err != nil {
			errs = append(errs, "ping0: "+ping0Result.err.Error())
		}
		if ippureResult.err != nil {
			errs = append(errs, "ippure: "+ippureResult.err.Error())
		}
		if iplarkResult.err != nil {
			errs = append(errs, "iplark: "+iplarkResult.err.Error())
		}
		if dklyResult.err != nil {
			errs = append(errs, "dkly: "+dklyResult.err.Error())
		}
		if len(errs) > 0 {
			return nil, fmt.Errorf("ip info empty: %s", strings.Join(errs, "; "))
		}
		return nil, fmt.Errorf("ip info empty")
	}

	info := primary.info
	for _, fallback := range fallbacks {
		info = mergeIPInfo(info, fallback.info)
	}
	p.fillScamScore(ctx, member, info)
	return info, nil
}

func (p *poolOutbound) fillScamScore(ctx context.Context, member *memberState, info *monitor.IPInfo) {
	if info == nil || info.IP == "" {
		return
	}
	ip := strings.TrimSpace(info.IP)
	if ip == "" {
		return
	}
	tag := ""
	if member != nil {
		tag = member.tag
	}
	if score, ok := p.cachedScamScore(tag, ip, scamSuccessTTL); ok {
		info.FraudScore = score
		return
	}
	scoreCtx, cancel := context.WithTimeout(ctx, scamTimeout)
	score, err := p.fetchScamScore(scoreCtx, member, ip)
	cancel()
	if err == nil && strings.TrimSpace(score) != "" {
		p.storeScamScore(tag, ip, score)
		info.FraudScore = strings.TrimSpace(score)
		return
	}
	if cached, lastSuccess, ok := p.scamCacheFallback(tag, ip); ok {
		if time.Since(lastSuccess) > scamFailureTTL && ctx.Err() == nil {
			retryCtx, retryCancel := context.WithTimeout(ctx, scamTimeout)
			retryScore, retryErr := p.fetchScamScore(retryCtx, member, ip)
			retryCancel()
			if retryErr == nil && strings.TrimSpace(retryScore) != "" {
				p.storeScamScore(tag, ip, retryScore)
				info.FraudScore = strings.TrimSpace(retryScore)
				return
			}
		}
		info.FraudScore = strings.TrimSpace(cached)
	}
}

func (p *poolOutbound) fetchScamScore(ctx context.Context, member *memberState, ip string) (string, error) {
	if member == nil || member.outbound == nil {
		return "", fmt.Errorf("missing outbound")
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "", fmt.Errorf("missing ip")
	}

	target := M.ParseSocksaddrHostPort(scamHost, 443)
	conn, err := member.outbound.DialContext(ctx, N.NetworkTCP, target)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(scamTimeout))
	tlsConn := tls.Client(conn, &tls.Config{ServerName: scamHost})
	if err := tlsConn.Handshake(); err != nil {
		return "", fmt.Errorf("tls handshake: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+scamHost+"/ip/"+ip, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Connection", "close")

	if err := req.Write(tlsConn); err != nil {
		return "", err
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("scamalytics status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	html := string(body)
	if matches := scamScore.FindStringSubmatch(html); len(matches) > 1 {
		return strings.TrimSpace(matches[1]), nil
	}
	return "", fmt.Errorf("scamalytics score not found")
}

func (p *poolOutbound) fetchIppureInfo(ctx context.Context, member *memberState, includeShared bool) (*monitor.IPInfo, error) {
	var resp *http.Response
	var err error
	for _, browserLike := range []bool{true, false} {
		resp, err = p.doHTTPSRequest(ctx, member, ipInfoHost, ipInfoPath, ipInfoTimeout, browserLike, "application/json,text/plain,*/*")
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ippure status %d", resp.StatusCode)
	}

	decoder := json.NewDecoder(resp.Body)
	decoder.UseNumber()
	var payload ippureInfoResponse
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}

	pureScore := ""
	if payload.FraudScore != "" {
		pureScore = payload.FraudScore.String() + "%"
	}

	botScore := ""
	if payload.BotScore != "" {
		botScore = strings.TrimSpace(payload.BotScore.String())
	} else if payload.HumanBotRatio != "" {
		botScore = strings.TrimSpace(payload.HumanBotRatio.String())
	}
	if botScore != "" && !strings.Contains(botScore, "%") {
		botScore = botScore + "%"
	}

	ipAttr := "机房"
	if payload.IsResidential {
		ipAttr = "住宅"
	}

	ipSrc := "原生"
	if payload.IsBroadcast {
		ipSrc = "广播"
	}

	location := joinLocation(payload.Country, payload.City)
	info := &monitor.IPInfo{
		IP:          payload.IP,
		PureScore:   pureScore,
		FraudScore:  pureScore,
		BotScore:    botScore,
		SharedUsers: "",
		IPAttr:      ipAttr,
		IPSrc:       ipSrc,
		Country:     payload.Country,
		City:        payload.City,
		Location:    location,
		ISP:         payload.ASOrganization,
		Source:      "ippure",
	}

	if payload.ASN != "" {
		if v, err := payload.ASN.Int64(); err == nil {
			info.ASN = v
		}
	}

	if includeShared {
		shareCtx, shareCancel := context.WithTimeout(ctx, ping0Timeout)
		sharedUsers, _ := p.fetchPing0Shared(shareCtx, member, payload.IP)
		shareCancel()
		if strings.TrimSpace(sharedUsers) != "" {
			info.SharedUsers = strings.TrimSpace(sharedUsers)
		}
	}

	return info, nil
}

func mergeIPInfo(primary, secondary *monitor.IPInfo) *monitor.IPInfo {
	if primary == nil {
		return secondary
	}
	if secondary == nil {
		return primary
	}
	out := *primary
	if strings.TrimSpace(out.IP) == "" {
		out.IP = secondary.IP
	}
	if strings.TrimSpace(out.PureScore) == "" {
		out.PureScore = secondary.PureScore
	}
	if strings.TrimSpace(out.BotScore) == "" {
		out.BotScore = secondary.BotScore
	}
	if strings.TrimSpace(out.SharedUsers) == "" {
		out.SharedUsers = secondary.SharedUsers
	}
	if strings.TrimSpace(out.IPAttr) == "" {
		out.IPAttr = secondary.IPAttr
	}
	if strings.TrimSpace(out.IPSrc) == "" {
		out.IPSrc = secondary.IPSrc
	}
	if strings.TrimSpace(out.Country) == "" {
		out.Country = secondary.Country
	}
	if strings.TrimSpace(out.City) == "" {
		out.City = secondary.City
	}
	if strings.TrimSpace(out.Location) == "" {
		out.Location = secondary.Location
	}
	if strings.TrimSpace(out.ISP) == "" {
		out.ISP = secondary.ISP
	}
	if out.ASN == 0 {
		out.ASN = secondary.ASN
	}
	if strings.TrimSpace(out.FraudScore) == "" {
		out.FraudScore = secondary.FraudScore
	}
	return &out
}

func parseIplarkInfo(headers http.Header, body string) (*monitor.IPInfo, bool) {
	info := &monitor.IPInfo{Source: "iplark"}
	hasData := false

	if ip := strings.TrimSpace(headers.Get("client-ip")); ip != "" {
		info.IP = ip
		hasData = true
	}
	if country := strings.TrimSpace(headers.Get("country")); country != "" {
		info.Country = country
		hasData = true
	}
	if city := strings.TrimSpace(headers.Get("city")); city != "" {
		info.City = city
		hasData = true
	}
	if asnRaw := strings.TrimSpace(headers.Get("asn")); asnRaw != "" {
		if asn, err := strconv.ParseInt(asnRaw, 10, 64); err == nil {
			info.ASN = asn
			hasData = true
		}
	}

	lines := strings.Split(body, "\n")
	firstLineSet := false
	for idx, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if !firstLineSet {
			firstLineSet = true
			if info.IP == "" {
				info.IP = line
				hasData = true
			}
		}
		if idx > 0 {
			asRange := iplarkASLine.FindStringSubmatchIndex(line)
			asMatch := iplarkASLine.FindStringSubmatch(line)
			if len(asRange) >= 4 && len(asMatch) > 1 {
				if info.ASN == 0 {
					if asn, err := strconv.ParseInt(asMatch[1], 10, 64); err == nil {
						info.ASN = asn
						hasData = true
					}
				}
				if asRange[0] > 0 &&
					strings.TrimSpace(info.Location) == "" &&
					strings.TrimSpace(info.Country) == "" &&
					strings.TrimSpace(info.City) == "" {
					locationPrefix := strings.TrimSpace(line[:asRange[0]])
					if locationPrefix != "" {
						info.Location = locationPrefix
						hasData = true
					}
				}
				org := strings.TrimSpace(line[asRange[1]:])
				if org != "" {
					info.ISP = org
					hasData = true
				}
			}
		}
	}

	if strings.TrimSpace(info.Location) == "" {
		info.Location = joinLocation(info.Country, info.City)
		if strings.TrimSpace(info.Location) != "" {
			hasData = true
		}
	}

	return info, hasData
}

func (p *poolOutbound) fetchIplarkInfo(ctx context.Context, member *memberState) (*monitor.IPInfo, error) {
	info, err := p.fetchIplarkInfoHTTPS(ctx, member)
	if err == nil {
		return info, nil
	}
	fallbackInfo, fallbackErr := p.fetchIplarkInfoHTTP(ctx, member)
	if fallbackErr == nil {
		return fallbackInfo, nil
	}
	return nil, fmt.Errorf("%v; http fallback: %v", err, fallbackErr)
}

func (p *poolOutbound) fetchIplarkInfoHTTPS(ctx context.Context, member *memberState) (*monitor.IPInfo, error) {
	if member == nil || member.outbound == nil {
		return nil, fmt.Errorf("missing outbound")
	}

	target := M.ParseSocksaddrHostPort(iplarkHost, 443)
	conn, err := member.outbound.DialContext(ctx, N.NetworkTCP, target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(iplarkTimeout))
	tlsConn := tls.Client(conn, &tls.Config{ServerName: iplarkHost})
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+iplarkHost+iplarkPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("Connection", "close")

	if err := req.Write(tlsConn); err != nil {
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	info, ok := parseIplarkInfo(resp.Header, string(body))
	if ok {
		return info, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("iplark status %d", resp.StatusCode)
	}
	return nil, fmt.Errorf("iplark parse failed")
}

func (p *poolOutbound) fetchIplarkInfoHTTP(ctx context.Context, member *memberState) (*monitor.IPInfo, error) {
	if member == nil || member.outbound == nil {
		return nil, fmt.Errorf("missing outbound")
	}

	target := M.ParseSocksaddrHostPort(iplarkHost, 80)
	conn, err := member.outbound.DialContext(ctx, N.NetworkTCP, target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(iplarkTimeout))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+iplarkHost+iplarkPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("Connection", "close")

	if err := req.Write(conn); err != nil {
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	info, ok := parseIplarkInfo(resp.Header, string(body))
	if ok {
		return info, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("iplark http status %d", resp.StatusCode)
	}
	return nil, fmt.Errorf("iplark http parse failed")
}

func (p *poolOutbound) fetchDKLYInfo(ctx context.Context, member *memberState) (*monitor.IPInfo, error) {
	if member == nil || member.outbound == nil {
		return nil, fmt.Errorf("missing outbound")
	}

	target := M.ParseSocksaddrHostPort(dklyHost, 443)
	conn, err := member.outbound.DialContext(ctx, N.NetworkTCP, target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(dklyTimeout))
	tlsConn := tls.Client(conn, &tls.Config{ServerName: dklyHost})
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+dklyHost+dklyPath+"?key="+dklyKey, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Connection", "close")

	if err := req.Write(tlsConn); err != nil {
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dkly status %d", resp.StatusCode)
	}

	decoder := json.NewDecoder(resp.Body)
	decoder.UseNumber()
	var payload dklyInfoResponse
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}

	info, ok := parseDKLYInfo(payload)
	if !ok {
		return nil, fmt.Errorf("dkly parse failed")
	}
	return info, nil
}

func parseDKLYInfo(payload dklyInfoResponse) (*monitor.IPInfo, bool) {
	info := &monitor.IPInfo{Source: "dkly"}
	hasData := false

	if ip := strings.TrimSpace(payload.IP); ip != "" {
		info.IP = ip
		hasData = true
	}

	countryName := strings.TrimSpace(payload.Location.Country.Name)
	countryCode := strings.TrimSpace(payload.Location.Country.Code)
	switch {
	case countryName != "":
		info.Country = countryName
	case countryCode != "":
		info.Country = countryCode
	}
	if info.Country != "" {
		hasData = true
	}

	if city := strings.TrimSpace(payload.Location.City); city != "" {
		info.City = city
		hasData = true
	}

	region := strings.TrimSpace(payload.Location.Region.Name)
	info.Location = joinLocation(info.Country, region, info.City)
	if info.Location != "" {
		hasData = true
	}

	isp := strings.TrimSpace(payload.Connection.Organization)
	if isp == "" {
		isp = strings.TrimSpace(payload.Company.Name)
	}
	if isp != "" {
		info.ISP = isp
		hasData = true
	}

	if payload.Connection.ASN != "" {
		if asn, err := payload.Connection.ASN.Int64(); err == nil {
			info.ASN = asn
			hasData = true
		}
	}

	riskCount := dklyRiskCount(payload.Security)
	hasClassificationInput := hasData ||
		riskCount > 0 ||
		strings.TrimSpace(payload.Connection.Type) != "" ||
		strings.TrimSpace(payload.Company.Type) != ""
	if hasClassificationInput {
		info.IPAttr = dklyIPAttr(payload.Connection.Type, payload.Company.Type, payload.Security)
		if info.IPAttr != "" {
			hasData = true
		}

		info.IPSrc = dklyIPSrc(payload.Security)
		if info.IPSrc != "" {
			hasData = true
		}

		info.PureScore = dklyPureScore(riskCount)
		if info.PureScore != "" {
			info.FraudScore = info.PureScore
			hasData = true
		}
	}

	return info, hasData
}

func dklyPureScore(riskCount int) string {
	score := 100 - 10*riskCount
	if score < 0 {
		score = 0
	}
	return strconv.Itoa(score) + "%"
}

func dklyRiskCount(security dklySecurityResponse) int {
	flags := []bool{
		security.IsAbuser,
		security.IsAttacker,
		security.IsBogon,
		security.IsCloudProvider,
		security.IsProxy,
		security.IsRelay,
		security.IsTor,
		security.IsTorExit,
		security.IsVPN,
		security.IsAnonymous,
		security.IsThreat,
	}
	risk := 0
	for _, flag := range flags {
		if flag {
			risk++
		}
	}
	return risk
}

func dklyIPAttr(connectionType, companyType string, security dklySecurityResponse) string {
	if security.IsCloudProvider {
		return "机房"
	}
	if attr := dklyTypeAttr(connectionType); attr != "" {
		return attr
	}
	return dklyTypeAttr(companyType)
}

func dklyTypeAttr(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "hosting", "datacenter", "business", "cloud", "server":
		return "机房"
	case "isp", "residential", "mobile", "consumer", "education", "government":
		return "住宅"
	default:
		return ""
	}
}

func dklyIPSrc(security dklySecurityResponse) string {
	if security.IsProxy ||
		security.IsRelay ||
		security.IsTor ||
		security.IsTorExit ||
		security.IsVPN ||
		security.IsAnonymous ||
		security.IsThreat ||
		security.IsAttacker ||
		security.IsAbuser ||
		security.IsBogon {
		return "广播"
	}
	return "原生"
}

func (p *poolOutbound) fetchPing0Info(ctx context.Context, member *memberState) (*monitor.IPInfo, error) {
	html, err := p.fetchPing0HTML(ctx, member, ping0Path)
	if err != nil {
		return nil, err
	}
	info, ok := parsePing0HTML(html)
	if !ok {
		return nil, fmt.Errorf("ping0 parse failed")
	}
	return info, nil
}

func (p *poolOutbound) fetchPing0Shared(ctx context.Context, member *memberState, ip string) (string, error) {
	path := ping0Path
	ip = strings.TrimSpace(ip)
	if ip != "" {
		path = "/ping/" + url.PathEscape(ip)
	}
	html, err := p.fetchPing0HTML(ctx, member, path)
	if err != nil {
		return "", err
	}
	return parsePing0Shared(html), nil
}

func (p *poolOutbound) fetchPing0HTML(ctx context.Context, member *memberState, path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		path = ping0Path
	}
	var resp *http.Response
	var err error
	for _, browserLike := range []bool{true, false} {
		resp, err = p.doHTTPSRequest(ctx, member, ping0Host, path, ping0Timeout, browserLike, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		if err == nil {
			break
		}
	}
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ping0 status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	html := string(body)

	if strings.Contains(html, "Just a moment") || strings.Contains(html, "cf-turnstile") || strings.Contains(html, "challenge-platform") {
		return "", fmt.Errorf("ping0 blocked")
	}
	return html, nil
}

func parsePing0Shared(html string) string {
	if matches := ping0UsecountAttr.FindStringSubmatch(html); len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	if matches := ping0UsecountBar.FindStringSubmatch(html); len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	if ping0NodesInit.MatchString(html) {
		return strconv.Itoa(len(ping0NodesPush.FindAllStringIndex(html, -1)))
	}
	return ""
}

func cleanPing0Label(raw string) string {
	raw = ping0HTMLTag.ReplaceAllString(raw, "")
	return strings.TrimSpace(raw)
}

func parsePing0HTML(html string) (*monitor.IPInfo, bool) {
	info := &monitor.IPInfo{Source: "ping0"}
	hasData := false

	if matches := ping0IPJS.FindStringSubmatch(html); len(matches) > 1 {
		info.IP = strings.TrimSpace(matches[1])
		if info.IP != "" {
			hasData = true
		}
	} else if matches := ping0IPHref.FindStringSubmatch(html); len(matches) > 1 {
		info.IP = strings.TrimSpace(matches[1])
		if info.IP != "" {
			hasData = true
		}
	}

	if matches := ping0Score.FindStringSubmatch(html); len(matches) > 1 {
		info.PureScore = strings.TrimSpace(matches[1]) + "%"
		hasData = true
	}

	if shared := strings.TrimSpace(parsePing0Shared(html)); shared != "" {
		info.SharedUsers = shared
		hasData = true
	}

	if matches := ping0Type.FindStringSubmatch(html); len(matches) > 1 {
		raw := cleanPing0Label(matches[1])
		switch {
		case strings.Contains(raw, "机房") || strings.Contains(strings.ToLower(raw), "idc"):
			info.IPAttr = "机房"
		case strings.Contains(raw, "家庭") || strings.Contains(raw, "住宅"):
			info.IPAttr = "住宅"
		default:
			info.IPAttr = raw
		}
		if info.IPAttr != "" {
			hasData = true
		}
	}

	if matches := ping0Native.FindStringSubmatch(html); len(matches) > 1 {
		raw := cleanPing0Label(matches[1])
		switch {
		case strings.Contains(raw, "广播"):
			info.IPSrc = "广播"
		case strings.Contains(raw, "原生"):
			info.IPSrc = "原生"
		default:
			info.IPSrc = raw
		}
		if info.IPSrc != "" {
			hasData = true
		}
	}

	info.SharedUsers = parsePing0Shared(html)
	if strings.TrimSpace(info.SharedUsers) != "" {
		hasData = true
	}

	return info, hasData
}
