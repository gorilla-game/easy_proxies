package monitor

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	extractorProtocolHTTP   = "http"
	extractorProtocolHTTPS  = "https"
	extractorProtocolSOCKS5 = "socks5"

	extractorRotationSticky     = "sticky"
	extractorRotationPerRequest = "per_request"
	extractorRotationTimed      = "timed"

	extractorSecurityAccountPassword = "account_password"

	extractorUsernameTemplateUIDUsername                          = "uid_username"
	extractorUsernameTemplateUIDUsernameRandomRotation            = "uid_username_random_rotation"
	extractorUsernameTemplateUIDUsernameSessionRandomLifeRotation = "uid_username_session_random_life_rotation"
	extractorUsernameTemplateUIDUsernameCountrySessionLife        = "uid_username_country_session_random_life_rotation"
	extractorUsernameTemplateUIDUsernameSessionLifeCountry        = "uid_username_session_random_life_rotation_country"

	extractorPasswordTemplatePlain                 = "password_plain"
	extractorPasswordTemplateCountryRandomRotation = "password_country_random_rotation"
	extractorPasswordTemplateCountrySessionLife    = "password_country_session_random_life_rotation"

	extractorOutputTemplateUserPassAtGateway = "user_pass_at_gateway"
	extractorOutputTemplateUserPassGateway   = "user_pass_gateway"
	extractorOutputTemplateGatewayAtUserPass = "gateway_at_user_pass"
	extractorOutputTemplateGatewayUserPass   = "gateway_user_pass"
	extractorOutputTemplateGatewayHashUser   = "gateway_hash_user_pass"

	extractorDelimiterEscapedNewline = "escaped_newline"
	extractorDelimiterNewline        = "newline"
	extractorDelimiterCarriageReturn = "carriage_return"
	extractorDelimiterTab            = "tab"
	extractorDelimiterComma          = "comma"
	extractorDelimiterCustom         = "custom"

	extractorFormatTXT  = "txt"
	extractorFormatCSV  = "csv"
	extractorFormatJSON = "json"

	extractorShortLinkParam = "sl"
)

type extractorOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

type extractorCountryOption struct {
	Value   string `json:"value"`
	Label   string `json:"label"`
	ISOCode string `json:"iso_code"`
	Count   int    `json:"count"`
}

type extractorRegionOption struct {
	Value      string `json:"value"`
	Label      string `json:"label"`
	Country    string `json:"country"`
	CountryISO string `json:"country_iso"`
	Count      int    `json:"count"`
}

type extractorGatewayOption struct {
	ID         string `json:"id"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	NodeName   string `json:"node_name,omitempty"`
	Country    string `json:"country,omitempty"`
	CountryISO string `json:"country_iso,omitempty"`
	Region     string `json:"region,omitempty"`
	IP         string `json:"ip,omitempty"`
	LatencyMs  int64  `json:"latency_ms"`
}

type extractorGenerateRequest struct {
	Country          string `json:"country"`
	CountryISO       string `json:"country_iso"`
	Region           string `json:"region"`
	Gateway          string `json:"gateway"`
	Protocol         string `json:"protocol"`
	RotationMode     string `json:"rotation_mode"`
	RotationSeconds  int    `json:"rotation_seconds"`
	SecurityMode     string `json:"security_mode"`
	UserID           string `json:"user_id"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	UsernameTemplate string `json:"username_template"`
	PasswordTemplate string `json:"password_template"`
	OutputTemplate   string `json:"output_template"`
	Delimiter        string `json:"delimiter"`
	CustomDelimiter  string `json:"custom_delimiter"`
	APIResponseFmt   string `json:"api_response_format"`
	Limit            int    `json:"limit"`
}

type extractorGeneratedEntry struct {
	Country         string `json:"country,omitempty"`
	CountryISO      string `json:"country_iso,omitempty"`
	Region          string `json:"region,omitempty"`
	GatewayHost     string `json:"gateway_host"`
	GatewayPort     int    `json:"gateway_port"`
	Gateway         string `json:"gateway"`
	Protocol        string `json:"protocol"`
	RotationMode    string `json:"rotation_mode"`
	RotationSeconds int    `json:"rotation_seconds"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	Connection      string `json:"connection"`
}

type extractorGenerateResult struct {
	Entries     []extractorGeneratedEntry
	Connections []string
	Content     string
	Request     extractorGenerateRequest
}

type extractorShortLink struct {
	Request   extractorGenerateRequest
	ExpiresAt time.Time
}

func (r *extractorGenerateRequest) normalize() {
	r.Country = strings.TrimSpace(r.Country)
	r.CountryISO = strings.ToUpper(strings.TrimSpace(r.CountryISO))
	r.Region = strings.TrimSpace(r.Region)
	r.Gateway = strings.TrimSpace(r.Gateway)
	r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
	r.RotationMode = strings.ToLower(strings.TrimSpace(r.RotationMode))
	r.SecurityMode = strings.ToLower(strings.TrimSpace(r.SecurityMode))
	r.UsernameTemplate = strings.ToLower(strings.TrimSpace(r.UsernameTemplate))
	r.PasswordTemplate = strings.ToLower(strings.TrimSpace(r.PasswordTemplate))
	r.OutputTemplate = strings.ToLower(strings.TrimSpace(r.OutputTemplate))
	r.Delimiter = strings.ToLower(strings.TrimSpace(r.Delimiter))
	r.CustomDelimiter = strings.TrimSpace(r.CustomDelimiter)
	r.APIResponseFmt = strings.ToLower(strings.TrimSpace(r.APIResponseFmt))
	r.UserID = strings.TrimSpace(r.UserID)
	r.Username = strings.TrimSpace(r.Username)
	r.Password = strings.TrimSpace(r.Password)

	switch r.Protocol {
	case extractorProtocolHTTP, extractorProtocolHTTPS, extractorProtocolSOCKS5:
	default:
		r.Protocol = extractorProtocolHTTP
	}

	switch r.RotationMode {
	case extractorRotationSticky, extractorRotationPerRequest, extractorRotationTimed:
	default:
		r.RotationMode = extractorRotationSticky
	}
	if r.RotationMode == extractorRotationTimed {
		if r.RotationSeconds <= 0 {
			r.RotationSeconds = 300
		}
	} else {
		r.RotationSeconds = 0
	}

	if r.SecurityMode == "" {
		r.SecurityMode = extractorSecurityAccountPassword
	}
	if r.SecurityMode != extractorSecurityAccountPassword {
		r.SecurityMode = extractorSecurityAccountPassword
	}

	if r.UsernameTemplate == "" {
		r.UsernameTemplate = extractorUsernameTemplateUIDUsername
	}
	switch r.UsernameTemplate {
	case extractorUsernameTemplateUIDUsername,
		extractorUsernameTemplateUIDUsernameRandomRotation,
		extractorUsernameTemplateUIDUsernameSessionRandomLifeRotation,
		extractorUsernameTemplateUIDUsernameCountrySessionLife,
		extractorUsernameTemplateUIDUsernameSessionLifeCountry:
	default:
		r.UsernameTemplate = extractorUsernameTemplateUIDUsername
	}

	if r.PasswordTemplate == "" {
		r.PasswordTemplate = extractorPasswordTemplatePlain
	}
	switch r.PasswordTemplate {
	case extractorPasswordTemplatePlain,
		extractorPasswordTemplateCountryRandomRotation,
		extractorPasswordTemplateCountrySessionLife:
	default:
		r.PasswordTemplate = extractorPasswordTemplatePlain
	}

	if r.OutputTemplate == "" {
		r.OutputTemplate = extractorOutputTemplateUserPassAtGateway
	}
	switch r.OutputTemplate {
	case extractorOutputTemplateUserPassAtGateway,
		extractorOutputTemplateUserPassGateway,
		extractorOutputTemplateGatewayAtUserPass,
		extractorOutputTemplateGatewayUserPass,
		extractorOutputTemplateGatewayHashUser:
	default:
		r.OutputTemplate = extractorOutputTemplateUserPassAtGateway
	}

	if r.Delimiter == "" {
		r.Delimiter = extractorDelimiterNewline
	}
	switch r.Delimiter {
	case extractorDelimiterEscapedNewline,
		extractorDelimiterNewline,
		extractorDelimiterCarriageReturn,
		extractorDelimiterTab,
		extractorDelimiterComma,
		extractorDelimiterCustom:
	default:
		r.Delimiter = extractorDelimiterNewline
	}

	if r.APIResponseFmt == "" {
		r.APIResponseFmt = extractorFormatTXT
	}
	switch r.APIResponseFmt {
	case extractorFormatTXT, extractorFormatCSV, extractorFormatJSON:
	default:
		r.APIResponseFmt = extractorFormatTXT
	}

	if r.Limit < 0 {
		r.Limit = 0
	}
	if r.Limit > 1000 {
		r.Limit = 1000
	}
}

func (s *Server) handleExtractorOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	gateways, err := s.listExtractorGateways(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}

	countries := buildExtractorCountries(gateways)
	regions := buildExtractorRegions(gateways)

	writeJSON(w, map[string]any{
		"countries":          countries,
		"regions":            regions,
		"gateways":           gateways,
		"protocols":          extractorProtocolOptions(),
		"rotation_modes":     extractorRotationOptions(),
		"security_modes":     extractorSecurityOptions(),
		"username_templates": extractorUsernameTemplateOptions(),
		"password_templates": extractorPasswordTemplateOptions(),
		"output_templates":   extractorOutputTemplateOptions(),
		"delimiter_options":  extractorDelimiterOptions(),
		"api_formats":        extractorAPIFormatOptions(),
		"defaults": map[string]any{
			"protocol":            extractorProtocolHTTP,
			"rotation_mode":       extractorRotationSticky,
			"rotation_seconds":    300,
			"security_mode":       extractorSecurityAccountPassword,
			"username_template":   extractorUsernameTemplateUIDUsername,
			"password_template":   extractorPasswordTemplatePlain,
			"output_template":     extractorOutputTemplateUserPassAtGateway,
			"delimiter":           extractorDelimiterNewline,
			"api_response_format": extractorFormatTXT,
		},
	})
}

func (s *Server) handleExtractorGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req extractorGenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "请求格式错误"})
		return
	}
	req.normalize()

	result, err := s.generateExtractorResult(r.Context(), req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}

	csvContent, err := renderExtractorCSV(result.Entries)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, map[string]any{
		"count":       len(result.Entries),
		"content":     result.Content,
		"connections": result.Connections,
		"entries":     result.Entries,
		"csv":         csvContent,
		"request":     result.Request,
	})
}

func (s *Server) handleExtractorLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req extractorGenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "请求格式错误"})
		return
	}
	req.normalize()

	result, err := s.generateExtractorResult(r.Context(), req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}

	payload, err := encodeExtractorPayload(req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}

	query := url.Values{}
	query.Set("payload", payload)
	if req.APIResponseFmt != "" {
		query.Set("format", req.APIResponseFmt)
	}
	if token := s.preferredExtractorToken(r); token != "" {
		query.Set("token", token)
	}

	fetchBaseURL := s.extractorFetchBaseURL(r)
	fetchURL := fetchBaseURL + "?" + query.Encode()
	shortCode, shortExpiresAt, err := s.createSignedExtractorShortLink(req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	shortQuery := url.Values{}
	shortQuery.Set(extractorShortLinkParam, shortCode)
	shortFetchURL := fetchBaseURL + "?" + shortQuery.Encode()
	preview := ""
	if len(result.Connections) > 0 {
		preview = result.Connections[0]
	}

	writeJSON(w, map[string]any{
		"fetch_url":            fetchURL,
		"signed_short_url":     shortFetchURL,
		"signed_short_code":    shortCode,
		"signed_short_expires": shortExpiresAt,
		"api_response_format":  req.APIResponseFmt,
		"preview_count":        len(result.Entries),
		"preview_first_line":   preview,
		"has_token_in_query":   query.Get("token") != "",
	})
}

func (s *Server) handleExtractorFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var (
		req extractorGenerateRequest
		err error
	)
	shortCode := strings.TrimSpace(r.URL.Query().Get(extractorShortLinkParam))
	if shortCode != "" {
		req, err = s.resolveSignedExtractorShortLink(shortCode)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
	} else {
		if s.extractorAuthRequired() && !s.isExtractorFetchAuthorized(r) {
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(w, map[string]any{"error": "未授权，请提供 token"})
			return
		}

		payload := strings.TrimSpace(r.URL.Query().Get("payload"))
		if payload == "" {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "缺少 payload 或 sl 参数"})
			return
		}
		req, err = decodeExtractorPayload(payload)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "payload 无效"})
			return
		}
	}

	if format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))); format != "" {
		req.APIResponseFmt = format
	}
	req.normalize()

	result, err := s.generateExtractorResult(r.Context(), req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}

	switch req.APIResponseFmt {
	case extractorFormatCSV:
		content, err := renderExtractorCSV(result.Entries)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=extractor.csv")
		_, _ = w.Write([]byte(content))
	case extractorFormatJSON:
		writeJSON(w, map[string]any{
			"count":       len(result.Entries),
			"entries":     result.Entries,
			"connections": result.Connections,
			"request":     result.Request,
		})
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=extractor.txt")
		_, _ = w.Write([]byte(result.Content))
	}
}

func (s *Server) listExtractorGateways(ctx context.Context) ([]extractorGatewayOption, error) {
	rows, err := s.mgr.ListCurrentNodes(ctx)
	if err != nil {
		return nil, err
	}

	externalIP, _, _ := s.getSettings()
	gateways := make(map[string]extractorGatewayOption)
	for _, row := range rows {
		host := normalizeGatewayHost(row.ListenAddr, row.IP, externalIP)
		if host == "" || row.ListenPort == 0 {
			continue
		}
		port := int(row.ListenPort)
		id := fmt.Sprintf("%s:%d", host, port)
		country := strings.TrimSpace(row.Country)
		if country == "" {
			country = strings.TrimSpace(row.Location)
		}
		region := strings.TrimSpace(row.City)
		if region == "" {
			region = strings.TrimSpace(row.Location)
		}
		if region == "" {
			region = country
		}
		cand := extractorGatewayOption{
			ID:         id,
			Host:       host,
			Port:       port,
			NodeName:   strings.TrimSpace(row.Name),
			Country:    country,
			CountryISO: countryISO(country, row.Location),
			Region:     region,
			IP:         strings.TrimSpace(row.IP),
			LatencyMs:  row.LatencyMs,
		}
		if prev, ok := gateways[id]; !ok {
			gateways[id] = cand
		} else {
			gateways[id] = betterGateway(prev, cand)
		}
	}

	if len(gateways) == 0 {
		snaps := s.mgr.SnapshotFiltered(true)
		for _, snap := range snaps {
			host := normalizeGatewayHost(snap.ListenAddress, "", externalIP)
			if host == "" || snap.Port == 0 {
				continue
			}
			port := int(snap.Port)
			id := fmt.Sprintf("%s:%d", host, port)

			country := strings.TrimSpace(snap.Country)
			if country == "" && snap.IPInfo != nil {
				country = strings.TrimSpace(snap.IPInfo.Country)
			}
			region := strings.TrimSpace(snap.Region)
			if region == "" && snap.IPInfo != nil {
				region = strings.TrimSpace(snap.IPInfo.City)
			}
			if region == "" {
				region = country
			}
			ip := ""
			if snap.IPInfo != nil {
				ip = strings.TrimSpace(snap.IPInfo.IP)
			}
			cand := extractorGatewayOption{
				ID:         id,
				Host:       host,
				Port:       port,
				NodeName:   strings.TrimSpace(snap.Name),
				Country:    country,
				CountryISO: countryISO(country, region),
				Region:     region,
				IP:         ip,
				LatencyMs:  snap.LastLatencyMs,
			}
			if prev, ok := gateways[id]; !ok {
				gateways[id] = cand
			} else {
				gateways[id] = betterGateway(prev, cand)
			}
		}
	}

	out := make([]extractorGatewayOption, 0, len(gateways))
	for _, gw := range gateways {
		if gw.CountryISO == "" {
			gw.CountryISO = "ZZ"
		}
		out = append(out, gw)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Host == out[j].Host {
			return out[i].Port < out[j].Port
		}
		return out[i].Host < out[j].Host
	})
	return out, nil
}

func (s *Server) generateExtractorResult(ctx context.Context, req extractorGenerateRequest) (extractorGenerateResult, error) {
	gateways, err := s.listExtractorGateways(ctx)
	if err != nil {
		return extractorGenerateResult{}, err
	}
	if len(gateways) == 0 {
		return extractorGenerateResult{}, errors.New("当前没有可用网关节点")
	}

	filtered := filterExtractorGateways(gateways, req)
	if len(filtered) == 0 {
		return extractorGenerateResult{}, errors.New("筛选后没有可用网关节点")
	}
	if req.Limit > 0 && len(filtered) > req.Limit {
		filtered = filtered[:req.Limit]
	}

	rotation := rotationIntervalValue(req)
	entries := make([]extractorGeneratedEntry, 0, len(filtered))
	connections := make([]string, 0, len(filtered))
	for _, gw := range filtered {
		sessionID := randomSessionID()
		iso := req.CountryISO
		if iso == "" {
			iso = gw.CountryISO
		}
		if iso == "" {
			iso = countryISO(req.Country, req.Region)
		}
		if iso == "" {
			iso = "ZZ"
		}

		username := renderExtractorUsername(req, iso, sessionID, rotation)
		password := renderExtractorPassword(req, iso, sessionID, rotation)
		connection := formatExtractorConnection(req.OutputTemplate, username, password, gw.Host, gw.Port)
		entry := extractorGeneratedEntry{
			Country:         gw.Country,
			CountryISO:      iso,
			Region:          gw.Region,
			GatewayHost:     gw.Host,
			GatewayPort:     gw.Port,
			Gateway:         gw.ID,
			Protocol:        req.Protocol,
			RotationMode:    req.RotationMode,
			RotationSeconds: req.RotationSeconds,
			Username:        username,
			Password:        password,
			Connection:      connection,
		}
		entries = append(entries, entry)
		connections = append(connections, connection)
	}

	delimiter := resolveExtractorDelimiter(req.Delimiter, req.CustomDelimiter)
	return extractorGenerateResult{
		Entries:     entries,
		Connections: connections,
		Content:     strings.Join(connections, delimiter),
		Request:     req,
	}, nil
}

func renderExtractorUsername(req extractorGenerateRequest, countryISO, sessionID, rotation string) string {
	uid := req.UserID
	if uid == "" {
		uid = "uid"
	}
	name := req.Username
	if name == "" {
		name = "user"
	}

	switch req.UsernameTemplate {
	case extractorUsernameTemplateUIDUsername:
		return strings.Join([]string{uid, name}, "-")
	case extractorUsernameTemplateUIDUsernameRandomRotation:
		return strings.Join([]string{uid, name, sessionID, rotation}, "-")
	case extractorUsernameTemplateUIDUsernameSessionRandomLifeRotation:
		return strings.Join([]string{uid, name, "session", sessionID, "life", rotation}, "-")
	case extractorUsernameTemplateUIDUsernameCountrySessionLife:
		return strings.Join([]string{uid, name, countryISO, "session", sessionID, "life", rotation}, "-")
	case extractorUsernameTemplateUIDUsernameSessionLifeCountry:
		return strings.Join([]string{uid, name, "session", sessionID, "life", rotation, countryISO}, "-")
	default:
		return strings.Join([]string{uid, name}, "-")
	}
}

func renderExtractorPassword(req extractorGenerateRequest, countryISO, sessionID, rotation string) string {
	password := req.Password
	if password == "" {
		password = "password"
	}

	switch req.PasswordTemplate {
	case extractorPasswordTemplateCountryRandomRotation:
		return strings.Join([]string{password, countryISO, sessionID, rotation}, "-")
	case extractorPasswordTemplateCountrySessionLife:
		return strings.Join([]string{password, countryISO, "session", sessionID, "life", rotation}, "-")
	default:
		return password
	}
}

func formatExtractorConnection(template, username, password, host string, port int) string {
	gateway := fmt.Sprintf("%s:%d", host, port)
	switch template {
	case extractorOutputTemplateUserPassGateway:
		return fmt.Sprintf("%s:%s:%s", username, password, gateway)
	case extractorOutputTemplateGatewayAtUserPass:
		return fmt.Sprintf("%s@%s:%s", gateway, username, password)
	case extractorOutputTemplateGatewayUserPass:
		return fmt.Sprintf("%s:%s:%s", gateway, username, password)
	case extractorOutputTemplateGatewayHashUser:
		return fmt.Sprintf("%s##%s##%s", gateway, username, password)
	default:
		return fmt.Sprintf("%s:%s@%s", username, password, gateway)
	}
}

func renderExtractorCSV(entries []extractorGeneratedEntry) (string, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	if err := writer.Write([]string{"country", "country_iso", "region", "protocol", "gateway_host", "gateway_port", "gateway", "username", "password", "connection"}); err != nil {
		return "", err
	}
	for _, entry := range entries {
		record := []string{
			entry.Country,
			entry.CountryISO,
			entry.Region,
			entry.Protocol,
			entry.GatewayHost,
			strconv.Itoa(entry.GatewayPort),
			entry.Gateway,
			entry.Username,
			entry.Password,
			entry.Connection,
		}
		if err := writer.Write(record); err != nil {
			return "", err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func encodeExtractorPayload(req extractorGenerateRequest) (string, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeExtractorPayload(encoded string) (extractorGenerateRequest, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return extractorGenerateRequest{}, err
	}
	var req extractorGenerateRequest
	if err := json.Unmarshal(decoded, &req); err != nil {
		return extractorGenerateRequest{}, err
	}
	return req, nil
}

func (s *Server) createSignedExtractorShortLink(req extractorGenerateRequest) (code string, expiresAt time.Time, err error) {
	if s == nil {
		return "", time.Time{}, errors.New("服务未初始化")
	}
	id := newRandomHex(8)
	if id == "" {
		return "", time.Time{}, errors.New("生成短链失败")
	}
	expiresAt = time.Now().UTC().Add(s.extractorLinkTTL)
	exp := expiresAt.Unix()
	sig := s.signExtractorShortLink(id, exp)
	code = fmt.Sprintf("%s.%s.%s", id, strconv.FormatInt(exp, 36), sig)

	s.extractorLinkMu.Lock()
	s.extractorLinks[id] = extractorShortLink{
		Request:   req,
		ExpiresAt: expiresAt,
	}
	s.cleanupExpiredExtractorLinksLocked(time.Now())
	s.extractorLinkMu.Unlock()
	return code, expiresAt, nil
}

func (s *Server) resolveSignedExtractorShortLink(code string) (extractorGenerateRequest, error) {
	if s == nil {
		return extractorGenerateRequest{}, errors.New("服务未初始化")
	}
	parts := strings.Split(strings.TrimSpace(code), ".")
	if len(parts) != 3 {
		return extractorGenerateRequest{}, errors.New("签名短链格式无效")
	}

	id := strings.TrimSpace(parts[0])
	expPart := strings.TrimSpace(parts[1])
	sig := strings.ToLower(strings.TrimSpace(parts[2]))
	if id == "" || expPart == "" || sig == "" {
		return extractorGenerateRequest{}, errors.New("签名短链格式无效")
	}

	exp, err := strconv.ParseInt(expPart, 36, 64)
	if err != nil || exp <= 0 {
		return extractorGenerateRequest{}, errors.New("签名短链过期时间无效")
	}
	if now := time.Now().UTC(); now.After(time.Unix(exp, 0).UTC()) {
		return extractorGenerateRequest{}, errors.New("签名短链已过期")
	}
	if !hmac.Equal([]byte(sig), []byte(s.signExtractorShortLink(id, exp))) {
		return extractorGenerateRequest{}, errors.New("签名短链校验失败")
	}

	s.extractorLinkMu.Lock()
	defer s.extractorLinkMu.Unlock()
	entry, ok := s.extractorLinks[id]
	if !ok {
		return extractorGenerateRequest{}, errors.New("签名短链不存在或已失效")
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(s.extractorLinks, id)
		return extractorGenerateRequest{}, errors.New("签名短链已过期")
	}
	return entry.Request, nil
}

func (s *Server) signExtractorShortLink(id string, exp int64) string {
	key := s.extractorShortLinkSignKey()
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(id))
	_, _ = mac.Write([]byte{'.'})
	_, _ = mac.Write([]byte(strconv.FormatInt(exp, 10)))
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

func (s *Server) extractorShortLinkSignKey() []byte {
	s.cfgMu.RLock()
	apiToken := strings.TrimSpace(s.cfg.APIToken)
	password := strings.TrimSpace(s.cfg.Password)
	s.cfgMu.RUnlock()
	if apiToken != "" {
		return []byte("api-token:" + apiToken)
	}
	if password != "" {
		return []byte("password:" + password)
	}
	s.extractorLinkMu.RLock()
	secret := s.extractorSecret
	s.extractorLinkMu.RUnlock()
	if secret == "" {
		secret = "easy-proxies-extractor"
	}
	return []byte(secret)
}

func (s *Server) cleanupExpiredExtractorLinks(now time.Time) {
	if s == nil {
		return
	}
	s.extractorLinkMu.Lock()
	s.cleanupExpiredExtractorLinksLocked(now)
	s.extractorLinkMu.Unlock()
}

func (s *Server) cleanupExpiredExtractorLinksLocked(now time.Time) {
	if s == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	for key, entry := range s.extractorLinks {
		if now.After(entry.ExpiresAt) {
			delete(s.extractorLinks, key)
		}
	}
}

func (s *Server) extractorFetchBaseURL(r *http.Request) string {
	scheme := "http"
	if r != nil {
		if proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); proto != "" {
			scheme = strings.ToLower(strings.TrimSpace(strings.Split(proto, ",")[0]))
		} else if r.TLS != nil {
			scheme = "https"
		}
	}

	host := ""
	if r != nil {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		s.cfgMu.RLock()
		host = strings.TrimSpace(s.cfg.Listen)
		s.cfgMu.RUnlock()
	}
	if host == "" {
		host = "127.0.0.1:9090"
	}
	return fmt.Sprintf("%s://%s/api/extractor/fetch", scheme, host)
}

func (s *Server) preferredExtractorToken(r *http.Request) string {
	s.cfgMu.RLock()
	apiToken := strings.TrimSpace(s.cfg.APIToken)
	s.cfgMu.RUnlock()
	if apiToken != "" {
		return apiToken
	}
	if r == nil {
		return ""
	}
	if cookie, err := r.Cookie("session_token"); err == nil && s.isTokenValid(cookie.Value) {
		return cookie.Value
	}
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if s.isTokenValid(token) {
			return token
		}
	}
	return ""
}

func (s *Server) extractorAuthRequired() bool {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg.Password != "" || strings.TrimSpace(s.cfg.APIToken) != ""
}

func (s *Server) isExtractorFetchAuthorized(r *http.Request) bool {
	if r == nil {
		return false
	}
	if token := strings.TrimSpace(r.URL.Query().Get("token")); token != "" {
		if s.isTokenValid(token) {
			return true
		}
	}
	return s.isAuthorized(r)
}

func resolveExtractorDelimiter(delimiter, custom string) string {
	switch delimiter {
	case extractorDelimiterEscapedNewline:
		return `\n`
	case extractorDelimiterCarriageReturn:
		return "\r"
	case extractorDelimiterTab:
		return "\t"
	case extractorDelimiterComma:
		return ","
	case extractorDelimiterCustom:
		if custom == "" {
			return "\n"
		}
		return decodeEscapedDelimiter(custom)
	default:
		return "\n"
	}
}

func decodeEscapedDelimiter(input string) string {
	replacer := strings.NewReplacer(
		`\\n`, "\n",
		`\\r`, "\r",
		`\\t`, "\t",
	)
	return replacer.Replace(input)
}

func filterExtractorGateways(gateways []extractorGatewayOption, req extractorGenerateRequest) []extractorGatewayOption {
	if len(gateways) == 0 {
		return nil
	}
	country := strings.TrimSpace(req.Country)
	countryISO := strings.ToUpper(strings.TrimSpace(req.CountryISO))
	region := strings.TrimSpace(req.Region)
	gateway := strings.TrimSpace(req.Gateway)

	out := make([]extractorGatewayOption, 0, len(gateways))
	for _, gw := range gateways {
		if gateway != "" && !strings.EqualFold(gateway, gw.ID) {
			continue
		}
		if country != "" && !containsFold(gw.Country, country) {
			continue
		}
		if countryISO != "" && !strings.EqualFold(gw.CountryISO, countryISO) {
			continue
		}
		if region != "" && !containsFold(gw.Region, region) {
			continue
		}
		out = append(out, gw)
	}
	return out
}

func rotationIntervalValue(req extractorGenerateRequest) string {
	switch req.RotationMode {
	case extractorRotationPerRequest:
		return "req"
	case extractorRotationTimed:
		if req.RotationSeconds > 0 {
			return fmt.Sprintf("%ds", req.RotationSeconds)
		}
		return "300s"
	default:
		return "sticky"
	}
}

func randomSessionID() string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "session"
	}
	return hex.EncodeToString(buf)
}

func normalizeGatewayHost(listenAddr, ip, externalIP string) string {
	host := strings.TrimSpace(listenAddr)
	if host == "" {
		host = strings.TrimSpace(ip)
	}
	if host == "0.0.0.0" || host == "::" || host == "[::]" {
		if strings.TrimSpace(externalIP) != "" {
			host = strings.TrimSpace(externalIP)
		} else if strings.TrimSpace(ip) != "" {
			host = strings.TrimSpace(ip)
		}
	}
	host = strings.Trim(host, "[]")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = strings.TrimSpace(h)
	}
	return strings.TrimSpace(host)
}

func betterGateway(current, candidate extractorGatewayOption) extractorGatewayOption {
	if strings.TrimSpace(current.NodeName) == "" && strings.TrimSpace(candidate.NodeName) != "" {
		current.NodeName = candidate.NodeName
	}
	if strings.TrimSpace(current.Country) == "" && strings.TrimSpace(candidate.Country) != "" {
		current.Country = candidate.Country
	}
	if strings.TrimSpace(current.CountryISO) == "" && strings.TrimSpace(candidate.CountryISO) != "" {
		current.CountryISO = candidate.CountryISO
	}
	if strings.TrimSpace(current.Region) == "" && strings.TrimSpace(candidate.Region) != "" {
		current.Region = candidate.Region
	}
	if strings.TrimSpace(current.IP) == "" && strings.TrimSpace(candidate.IP) != "" {
		current.IP = candidate.IP
	}
	if (current.LatencyMs < 0 && candidate.LatencyMs >= 0) || (candidate.LatencyMs >= 0 && candidate.LatencyMs < current.LatencyMs) {
		current.LatencyMs = candidate.LatencyMs
	}
	return current
}

func buildExtractorCountries(gateways []extractorGatewayOption) []extractorCountryOption {
	type key struct {
		country string
		iso     string
	}
	counts := make(map[key]int)
	for _, gw := range gateways {
		country := strings.TrimSpace(gw.Country)
		if country == "" {
			country = "Unknown"
		}
		iso := strings.TrimSpace(gw.CountryISO)
		if iso == "" {
			iso = countryISO(country, gw.Region)
		}
		if iso == "" {
			iso = "ZZ"
		}
		counts[key{country: country, iso: iso}]++
	}
	out := make([]extractorCountryOption, 0, len(counts))
	for k, count := range counts {
		out = append(out, extractorCountryOption{
			Value:   k.country,
			Label:   fmt.Sprintf("%s (%s)", k.country, k.iso),
			ISOCode: k.iso,
			Count:   count,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Label < out[j].Label
	})
	return out
}

func buildExtractorRegions(gateways []extractorGatewayOption) []extractorRegionOption {
	type key struct {
		region  string
		country string
		iso     string
	}
	counts := make(map[key]int)
	for _, gw := range gateways {
		region := strings.TrimSpace(gw.Region)
		if region == "" {
			region = "Unknown"
		}
		country := strings.TrimSpace(gw.Country)
		if country == "" {
			country = "Unknown"
		}
		iso := strings.TrimSpace(gw.CountryISO)
		if iso == "" {
			iso = countryISO(country, region)
		}
		if iso == "" {
			iso = "ZZ"
		}
		counts[key{region: region, country: country, iso: iso}]++
	}
	out := make([]extractorRegionOption, 0, len(counts))
	for k, count := range counts {
		out = append(out, extractorRegionOption{
			Value:      k.region,
			Label:      fmt.Sprintf("%s (%s)", k.region, k.iso),
			Country:    k.country,
			CountryISO: k.iso,
			Count:      count,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Country == out[j].Country {
			return out[i].Label < out[j].Label
		}
		return out[i].Country < out[j].Country
	})
	return out
}

func extractorProtocolOptions() []extractorOption {
	return []extractorOption{
		{Value: extractorProtocolHTTP, Label: "HTTP"},
		{Value: extractorProtocolHTTPS, Label: "HTTPS"},
		{Value: extractorProtocolSOCKS5, Label: "SOCKS5"},
	}
}

func extractorRotationOptions() []extractorOption {
	return []extractorOption{
		{Value: extractorRotationSticky, Label: "粘性"},
		{Value: extractorRotationPerRequest, Label: "每次请求切换"},
		{Value: extractorRotationTimed, Label: "定时切换"},
	}
}

func extractorSecurityOptions() []extractorOption {
	return []extractorOption{
		{Value: extractorSecurityAccountPassword, Label: "账号/密码"},
	}
}

func extractorUsernameTemplateOptions() []extractorOption {
	return []extractorOption{
		{Value: extractorUsernameTemplateUIDUsername, Label: "用户ID-用户名"},
		{Value: extractorUsernameTemplateUIDUsernameRandomRotation, Label: "用户ID-用户名-随机session-IP轮转时间"},
		{Value: extractorUsernameTemplateUIDUsernameSessionRandomLifeRotation, Label: "用户ID-用户名-session-随机session-life-IP轮转时间"},
		{Value: extractorUsernameTemplateUIDUsernameCountrySessionLife, Label: "用户ID-用户名-国家ISO-session-随机session-life-IP轮转时间"},
		{Value: extractorUsernameTemplateUIDUsernameSessionLifeCountry, Label: "用户ID-用户名-session-随机session-life-IP轮转时间-国家ISO"},
	}
}

func extractorPasswordTemplateOptions() []extractorOption {
	return []extractorOption{
		{Value: extractorPasswordTemplatePlain, Label: "密码"},
		{Value: extractorPasswordTemplateCountryRandomRotation, Label: "密码-国家ISO-随机session-IP轮转时间"},
		{Value: extractorPasswordTemplateCountrySessionLife, Label: "密码-国家ISO-session-随机session-life-IP轮转时间"},
	}
}

func extractorOutputTemplateOptions() []extractorOption {
	return []extractorOption{
		{Value: extractorOutputTemplateUserPassAtGateway, Label: "线路连接用户名:线路连接密码@网关节点:端口"},
		{Value: extractorOutputTemplateUserPassGateway, Label: "线路连接用户名:线路连接密码:网关节点:端口"},
		{Value: extractorOutputTemplateGatewayAtUserPass, Label: "网关节点:端口@线路连接用户名:线路连接密码"},
		{Value: extractorOutputTemplateGatewayUserPass, Label: "网关节点:端口:线路连接用户名:线路连接密码"},
		{Value: extractorOutputTemplateGatewayHashUser, Label: "网关节点:端口##线路连接用户名##线路连接密码"},
	}
}

func extractorDelimiterOptions() []extractorOption {
	return []extractorOption{
		{Value: extractorDelimiterEscapedNewline, Label: `标准换行(\\n)`},
		{Value: extractorDelimiterNewline, Label: "换行(实际换行)"},
		{Value: extractorDelimiterCarriageReturn, Label: `回车(\\r)`},
		{Value: extractorDelimiterTab, Label: `Tab(\\t)`},
		{Value: extractorDelimiterComma, Label: "英文逗号(,)"},
		{Value: extractorDelimiterCustom, Label: "自定义分隔符"},
	}
}

func extractorAPIFormatOptions() []extractorOption {
	return []extractorOption{
		{Value: extractorFormatTXT, Label: "txt 格式"},
		{Value: extractorFormatCSV, Label: "csv 格式"},
		{Value: extractorFormatJSON, Label: "json 格式"},
	}
}

var countryISOAliases = map[string]string{
	"US":            "US",
	"USA":           "US",
	"UNITEDSTATES":  "US",
	"美国":            "US",
	"CN":            "CN",
	"CHINA":         "CN",
	"中国":            "CN",
	"JP":            "JP",
	"JAPAN":         "JP",
	"日本":            "JP",
	"SG":            "SG",
	"SINGAPORE":     "SG",
	"新加坡":           "SG",
	"HK":            "HK",
	"HONGKONG":      "HK",
	"香港":            "HK",
	"TW":            "TW",
	"TAIWAN":        "TW",
	"台湾":            "TW",
	"KR":            "KR",
	"KOREA":         "KR",
	"SOUTHKOREA":    "KR",
	"韩国":            "KR",
	"DE":            "DE",
	"GERMANY":       "DE",
	"德国":            "DE",
	"GB":            "GB",
	"UK":            "GB",
	"UNITEDKINGDOM": "GB",
	"英国":            "GB",
	"FR":            "FR",
	"FRANCE":        "FR",
	"法国":            "FR",
	"CA":            "CA",
	"CANADA":        "CA",
	"加拿大":           "CA",
	"AU":            "AU",
	"AUSTRALIA":     "AU",
	"澳大利亚":          "AU",
}

func countryISO(country, fallback string) string {
	for _, v := range []string{country, fallback} {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if iso := extractISOToken(v); iso != "" {
			return iso
		}
		key := normalizeCountryKey(v)
		if iso, ok := countryISOAliases[key]; ok {
			return iso
		}
	}
	return ""
}

func extractISOToken(input string) string {
	parts := strings.FieldsFunc(input, func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsDigit(r))
	})
	for _, part := range parts {
		if len(part) != 2 {
			continue
		}
		if isASCIIAlpha(part[0]) && isASCIIAlpha(part[1]) {
			return strings.ToUpper(part)
		}
	}
	if len(input) == 2 && isASCIIAlpha(input[0]) && isASCIIAlpha(input[1]) {
		return strings.ToUpper(input)
	}
	return ""
}

func normalizeCountryKey(input string) string {
	upper := strings.ToUpper(strings.TrimSpace(input))
	replacer := strings.NewReplacer(" ", "", "-", "", "_", "", ",", "", ".", "", "(", "", ")", "", "/", "", "\\", "")
	return replacer.Replace(upper)
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}
