package pool

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"easy_proxies/internal/monitor"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	ipInfoHost        = "my.123169.xyz"
	ipInfoPath        = "/v1/info"
	ipInfoMinInterval = 10 * time.Minute
	ipInfoTimeout     = 8 * time.Second
	ping0Host         = "ping0.cc"
	ping0Path         = "/"
	ping0Timeout      = 4 * time.Second
	scamHost          = "scamalytics.com"
	scamTimeout       = 4 * time.Second
	scamSuccessTTL    = 1 * time.Hour
	scamFailureTTL    = 24 * time.Hour
)

var (
	errPing0Blocked       = errors.New("ping0 blocked")
	errScamalyticsBlocked = errors.New("scamalytics blocked")

	ping0UsecountAttr = regexp.MustCompile(`usecount="([^"]+)"`)
	ping0UsecountBar  = regexp.MustCompile(`class="usecountbar"[^>]*>\s*([^<]+)\s*</div>`)
	ping0IPJS         = regexp.MustCompile(`window\.ip\s*=\s*'([^']+)'`)
	ping0IPHref       = regexp.MustCompile(`href="[^"]*?/ping/([0-9.]+)"`)
	ping0Type         = regexp.MustCompile(`(?s)<div class="line line-iptype">.*?<span class="label[^>]*>(.*?)</span>`)
	ping0Native       = regexp.MustCompile(`(?s)<div class="line line-nativeip">.*?<span class="label[^>]*>(.*?)</span>`)
	ping0Score        = regexp.MustCompile(`class="riskitem riskcurrent"[^>]*><span class="value">(\d+)%</span>`)
	ping0HTMLTag      = regexp.MustCompile(`<[^>]+>`)
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
	PureScore      json.Number `json:"pureScore"`
	PurityScore    json.Number `json:"purityScore"`
	BotScore       json.Number `json:"botScore"`
	BotScorePct    json.Number `json:"botScorePercent"`
	BotPercent     json.Number `json:"botPercent"`
	HumanBotRatio  json.Number `json:"humanBotRatio"`
	IsResidential  bool        `json:"isResidential"`
	IsBroadcast    bool        `json:"isBroadcast"`
}

func percentValue(candidates ...json.Number) string {
	for _, candidate := range candidates {
		text := strings.TrimSpace(candidate.String())
		if text == "" {
			continue
		}
		if !strings.Contains(text, "%") {
			text += "%"
		}
		return text
	}
	return ""
}

func statusFromValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return "ok"
}

func buildIPInfoFromIppurePayload(payload ippureInfoResponse) *monitor.IPInfo {
	pureScore := percentValue(payload.PureScore, payload.PurityScore)
	fraudScore := percentValue(payload.FraudScore)
	botScore := percentValue(payload.BotScore, payload.BotScorePct, payload.BotPercent, payload.HumanBotRatio)

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
		FraudScore:  fraudScore,
		FraudStatus: statusFromValue(fraudScore),
		BotScore:    botScore,
		BotStatus:   statusFromValue(botScore),
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

	return info
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

	type ipInfoResult struct {
		info *monitor.IPInfo
		err  error
	}

	var wg sync.WaitGroup
	wg.Add(2)

	ping0Ch := make(chan ipInfoResult, 1)
	ippureCh := make(chan ipInfoResult, 1)

	go func() {
		defer wg.Done()
		info, err := p.fetchPing0Info(ctx, member)
		ping0Ch <- ipInfoResult{info: info, err: err}
	}()

	go func() {
		defer wg.Done()
		info, err := p.fetchIppureInfo(ctx, member, false)
		ippureCh <- ipInfoResult{info: info, err: err}
	}()

	wg.Wait()
	ping0Result := <-ping0Ch
	ippureResult := <-ippureCh

	var primary, secondary *monitor.IPInfo
	var primaryErr, secondaryErr error
	if source == "ippure" {
		primary, primaryErr = ippureResult.info, ippureResult.err
		secondary, secondaryErr = ping0Result.info, ping0Result.err
	} else {
		primary, primaryErr = ping0Result.info, ping0Result.err
		secondary, secondaryErr = ippureResult.info, ippureResult.err
	}

	if primary == nil {
		primary = secondary
		primaryErr = secondaryErr
	}

	if primary == nil {
		if primaryErr != nil {
			return nil, primaryErr
		}
		if secondaryErr != nil {
			return nil, secondaryErr
		}
		return nil, fmt.Errorf("ip info empty")
	}

	info := mergeIPInfo(primary, secondary)
	p.fillScamScore(ctx, member, info)
	applyIPInfoStatuses(info, ping0Result.err, ippureResult.err)
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
	if strings.TrimSpace(info.FraudScore) != "" {
		info.FraudStatus = "ok"
		return
	}
	tag := ""
	if member != nil {
		tag = member.tag
	}
	if score, ok := p.cachedScamScore(tag, ip, scamSuccessTTL); ok {
		info.FraudScore = score
		info.FraudStatus = "ok"
		return
	}
	scoreCtx, cancel := context.WithTimeout(ctx, scamTimeout)
	score, err := p.fetchScamScore(scoreCtx, member, ip)
	cancel()
	if err == nil && strings.TrimSpace(score) != "" {
		p.storeScamScore(tag, ip, score)
		info.FraudScore = strings.TrimSpace(score)
		info.FraudStatus = "ok"
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
				info.FraudStatus = "ok"
				return
			}
		}
		info.FraudScore = strings.TrimSpace(cached)
		info.FraudStatus = "ok"
		return
	}
	if errors.Is(err, errScamalyticsBlocked) {
		info.FraudStatus = "blocked"
	} else if strings.TrimSpace(info.FraudScore) == "" {
		info.FraudStatus = "unavailable"
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

	if resp.StatusCode == http.StatusForbidden {
		return "", errScamalyticsBlocked
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("scamalytics status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	html := string(body)
	if strings.Contains(html, "cf-error-details") || strings.Contains(html, "you were blocked") || strings.Contains(html, "Attention Required!") {
		return "", errScamalyticsBlocked
	}
	if matches := scamScore.FindStringSubmatch(html); len(matches) > 1 {
		return strings.TrimSpace(matches[1]), nil
	}
	return "", fmt.Errorf("scamalytics score not found")
}

func (p *poolOutbound) fetchIppureInfo(ctx context.Context, member *memberState, includeShared bool) (*monitor.IPInfo, error) {
	if member == nil || member.outbound == nil {
		return nil, fmt.Errorf("missing outbound")
	}

	target := M.ParseSocksaddrHostPort(ipInfoHost, 443)
	conn, err := member.outbound.DialContext(ctx, N.NetworkTCP, target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(ipInfoTimeout))
	tlsConn := tls.Client(conn, &tls.Config{ServerName: ipInfoHost})
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+ipInfoHost+ipInfoPath, nil)
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
		return nil, fmt.Errorf("ippure status %d", resp.StatusCode)
	}

	decoder := json.NewDecoder(resp.Body)
	decoder.UseNumber()
	var payload ippureInfoResponse
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}

	info := buildIPInfoFromIppurePayload(payload)

	if includeShared {
		shareCtx, shareCancel := context.WithTimeout(ctx, ping0Timeout)
		sharedUsers, _ := p.fetchPing0Shared(shareCtx, member)
		shareCancel()
		if strings.TrimSpace(sharedUsers) != "" {
			info.SharedUsers = strings.TrimSpace(sharedUsers)
			info.SharedStatus = "ok"
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
	if strings.TrimSpace(out.BotStatus) == "" {
		out.BotStatus = secondary.BotStatus
	}
	if strings.TrimSpace(out.SharedUsers) == "" {
		out.SharedUsers = secondary.SharedUsers
	}
	if strings.TrimSpace(out.SharedStatus) == "" {
		out.SharedStatus = secondary.SharedStatus
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
	if strings.TrimSpace(out.FraudStatus) == "" {
		out.FraudStatus = secondary.FraudStatus
	}
	return &out
}

func (p *poolOutbound) fetchPing0Info(ctx context.Context, member *memberState) (*monitor.IPInfo, error) {
	html, err := p.fetchPing0HTML(ctx, member)
	if err != nil {
		return nil, err
	}
	info, ok := parsePing0HTML(html)
	if !ok {
		return nil, fmt.Errorf("ping0 parse failed")
	}
	return info, nil
}

func (p *poolOutbound) fetchPing0Shared(ctx context.Context, member *memberState) (string, error) {
	html, err := p.fetchPing0HTML(ctx, member)
	if err != nil {
		return "", err
	}
	return parsePing0Shared(html), nil
}

func (p *poolOutbound) fetchPing0HTML(ctx context.Context, member *memberState) (string, error) {
	if member == nil || member.outbound == nil {
		return "", fmt.Errorf("missing outbound")
	}

	target := M.ParseSocksaddrHostPort(ping0Host, 443)
	conn, err := member.outbound.DialContext(ctx, N.NetworkTCP, target)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(ping0Timeout))
	tlsConn := tls.Client(conn, &tls.Config{ServerName: ping0Host})
	if err := tlsConn.Handshake(); err != nil {
		return "", fmt.Errorf("tls handshake: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+ping0Host+ping0Path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml")
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
		return "", fmt.Errorf("ping0 status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	html := string(body)

	if strings.Contains(html, "Just a moment") || strings.Contains(html, "cf-turnstile") || strings.Contains(html, "challenge-platform") || strings.Contains(html, "AliyunCaptchaConfig") || strings.Contains(html, "onTurnstileSuccess") {
		return "", errPing0Blocked
	}
	return html, nil
}

func applyIPInfoStatuses(info *monitor.IPInfo, ping0Err, ippureErr error) {
	if info == nil {
		return
	}
	if strings.TrimSpace(info.FraudScore) != "" {
		info.FraudStatus = "ok"
	}
	if strings.TrimSpace(info.BotScore) != "" {
		info.BotStatus = "ok"
	} else if ippureErr == nil {
		info.BotStatus = "unavailable"
	}
	if strings.TrimSpace(info.SharedUsers) != "" {
		info.SharedStatus = "ok"
	} else if errors.Is(ping0Err, errPing0Blocked) {
		info.SharedStatus = "blocked"
	} else if ping0Err == nil {
		info.SharedStatus = "unavailable"
	}
}

func parsePing0Shared(html string) string {
	if matches := ping0UsecountAttr.FindStringSubmatch(html); len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	if matches := ping0UsecountBar.FindStringSubmatch(html); len(matches) > 1 {
		return strings.TrimSpace(matches[1])
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
