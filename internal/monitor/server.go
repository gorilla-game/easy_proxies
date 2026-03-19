package monitor

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	mathrand "math/rand"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"easy_proxies/internal/config"
	"golang.org/x/sync/semaphore"
)

//go:embed assets/index.html
var embeddedFS embed.FS

// Session represents a user session with expiration.
type Session struct {
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// NodeManager exposes config node CRUD and reload operations.
type NodeManager interface {
	ListConfigNodes(ctx context.Context) ([]config.NodeConfig, error)
	CreateNode(ctx context.Context, node config.NodeConfig) (config.NodeConfig, error)
	UpdateNode(ctx context.Context, name string, node config.NodeConfig) (config.NodeConfig, error)
	DeleteNode(ctx context.Context, name string) error
	DeleteAllNodes(ctx context.Context) error
	AddSubscription(ctx context.Context, subURL string) error
	DeleteSubscription(ctx context.Context, subURL string) error
	TriggerReload(ctx context.Context) error
}

// Sentinel errors for node operations.
var (
	ErrNodeNotFound         = errors.New("节点不存在")
	ErrNodeConflict         = errors.New("节点名称或端口已存在")
	ErrInvalidNode          = errors.New("无效的节点配置")
	ErrSubscriptionNotFound = errors.New("订阅不存在")
	ErrSubscriptionConflict = errors.New("订阅已存在")
	ErrInvalidSubscription  = errors.New("无效的订阅地址")
)

// SubscriptionRefresher interface for subscription manager.
type SubscriptionRefresher interface {
	RefreshNow() error
	Status() SubscriptionStatus
}

// SubscriptionStatus represents subscription refresh status.
type SubscriptionStatus struct {
	LastRefresh     time.Time `json:"last_refresh"`
	NextRefresh     time.Time `json:"next_refresh"`
	NodeCount       int       `json:"node_count"`
	LastError       string    `json:"last_error,omitempty"`
	RefreshCount    int       `json:"refresh_count"`
	IsRefreshing    bool      `json:"is_refreshing"`
	NodesModified   bool      `json:"nodes_modified"` // True if nodes.txt was modified since last refresh
	ProgressTotal   int       `json:"progress_total"`
	ProgressCurrent int       `json:"progress_current"`
	ProgressNodes   int       `json:"progress_nodes"`
	ProgressMessage string    `json:"progress_message,omitempty"`
}

// Server exposes HTTP endpoints for monitoring.
type Server struct {
	cfg    Config
	cfgMu  sync.RWMutex   // 保护动态配置字段
	cfgSrc *config.Config // 可持久化的配置对象
	mgr    *Manager
	srv    *http.Server
	logger *log.Logger

	// Session management
	sessionMu  sync.RWMutex
	sessions   map[string]*Session
	sessionTTL time.Duration

	// Extractor signed short links
	extractorLinkMu  sync.RWMutex
	extractorLinks   map[string]extractorShortLink
	extractorLinkTTL time.Duration
	extractorSecret  string

	// Concurrency control
	probeSem *semaphore.Weighted

	subRefresher SubscriptionRefresher
	nodeMgr      NodeManager
}

// NewServer constructs a server; it can be nil when disabled.
func NewServer(cfg Config, mgr *Manager, logger *log.Logger) *Server {
	if !cfg.Enabled || mgr == nil {
		return nil
	}
	if logger == nil {
		logger = log.Default()
	}

	// Calculate max concurrent probes
	maxConcurrentProbes := int64(runtime.NumCPU() * 4)
	if maxConcurrentProbes < 10 {
		maxConcurrentProbes = 10
	}

	s := &Server{
		cfg:              cfg,
		mgr:              mgr,
		logger:           logger,
		sessions:         make(map[string]*Session),
		sessionTTL:       24 * time.Hour,
		extractorLinks:   make(map[string]extractorShortLink),
		extractorLinkTTL: 24 * time.Hour,
		extractorSecret:  newRandomHex(32),
		probeSem:         semaphore.NewWeighted(maxConcurrentProbes),
	}
	if s.extractorSecret == "" {
		s.extractorSecret = fmt.Sprintf("extractor-%d", time.Now().UnixNano())
	}

	// Start session cleanup goroutine
	go s.cleanupExpiredSessions()

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/docs", s.handleDocs)
	mux.HandleFunc("/api/openapi.json", s.handleOpenAPIJSON)
	mux.HandleFunc("/api/auth", s.handleAuth)
	mux.HandleFunc("/api/settings", s.withAuth(s.handleSettings))
	mux.HandleFunc("/api/nodes", s.withAuth(s.handleNodes))
	mux.HandleFunc("/api/nodes/current", s.withAuth(s.handleCurrentNodes))
	mux.HandleFunc("/api/nodes/events", s.withAuth(s.handleNodeEvents))
	mux.HandleFunc("/api/extractor/options", s.withAuth(s.handleExtractorOptions))
	mux.HandleFunc("/api/extractor/generate", s.withAuth(s.handleExtractorGenerate))
	mux.HandleFunc("/api/extractor/link", s.withAuth(s.handleExtractorLink))
	mux.HandleFunc("/api/extractor/fetch", s.handleExtractorFetch)
	mux.HandleFunc("/api/nodes/config", s.withAuth(s.handleConfigNodes))
	mux.HandleFunc("/api/nodes/config/", s.withAuth(s.handleConfigNodeItem))
	mux.HandleFunc("/api/nodes/probe-all", s.withAuth(s.handleProbeAll))
	mux.HandleFunc("/api/nodes/", s.withAuth(s.handleNodeAction))
	mux.HandleFunc("/api/subscriptions", s.withAuth(s.handleSubscriptions))
	mux.HandleFunc("/api/debug", s.withAuth(s.handleDebug))
	mux.HandleFunc("/api/export/filter", s.withAuth(s.handleExportFilter))
	mux.HandleFunc("/api/export", s.withAuth(s.handleExport))
	mux.HandleFunc("/api/subscription/status", s.withAuth(s.handleSubscriptionStatus))
	mux.HandleFunc("/api/subscription/refresh", s.withAuth(s.handleSubscriptionRefresh))
	mux.HandleFunc("/api/reload", s.withAuth(s.handleReload))
	s.srv = &http.Server{Addr: cfg.Listen, Handler: s.withCORS(mux)}
	return s
}

// SetSubscriptionRefresher sets the subscription refresher for API endpoints.
func (s *Server) SetSubscriptionRefresher(sr SubscriptionRefresher) {
	if s != nil {
		s.subRefresher = sr
	}
}

// SetNodeManager enables config-node CRUD endpoints.
func (s *Server) SetNodeManager(nm NodeManager) {
	if s != nil {
		s.nodeMgr = nm
	}
}

// SetConfig binds the persistable config object for settings API.
func (s *Server) SetConfig(cfg *config.Config) {
	if s == nil {
		return
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	s.cfgSrc = cfg
	if cfg != nil {
		s.cfg.ExternalIP = cfg.ExternalIP
		s.cfg.ProbeTarget = cfg.Management.ProbeTarget
		s.cfg.SkipCertVerify = cfg.SkipCertVerify
		s.cfg.APIToken = cfg.Management.APIToken
		s.cfg.CORSOrigins = append([]string(nil), cfg.Management.CORSOrigins...)
	}
}

func (s *Server) proxyAuth() (string, string) {
	s.cfgMu.RLock()
	cfgSrc := s.cfgSrc
	cfg := s.cfg
	s.cfgMu.RUnlock()
	if cfgSrc == nil {
		return cfg.ProxyUsername, cfg.ProxyPassword
	}
	mode := strings.TrimSpace(strings.ToLower(cfgSrc.Mode))
	if mode == "multi_port" {
		mode = "multi-port"
	}
	if mode == "multi-port" || mode == "hybrid" {
		return cfgSrc.MultiPort.Username, cfgSrc.MultiPort.Password
	}
	return cfgSrc.Listener.Username, cfgSrc.Listener.Password
}

// getSettings returns current dynamic settings (thread-safe).
func (s *Server) getSettings() (externalIP, probeTarget string, skipCertVerify bool) {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg.ExternalIP, s.cfg.ProbeTarget, s.cfg.SkipCertVerify
}

// updateSettings updates dynamic settings and persists to config file.
func (s *Server) updateSettings(externalIP, probeTarget string, skipCertVerify bool) error {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	s.cfg.ExternalIP = externalIP
	s.cfg.ProbeTarget = probeTarget
	s.cfg.SkipCertVerify = skipCertVerify

	if s.cfgSrc == nil {
		return errors.New("配置存储未初始化")
	}

	s.cfgSrc.ExternalIP = externalIP
	s.cfgSrc.Management.ProbeTarget = probeTarget
	s.cfgSrc.SkipCertVerify = skipCertVerify

	if err := s.cfgSrc.SaveSettings(); err != nil {
		return fmt.Errorf("保存配置失败: %w", err)
	}
	return nil
}

// Start launches the HTTP server.
func (s *Server) Start(ctx context.Context) {
	if s == nil || s.srv == nil {
		return
	}
	s.logger.Printf("Starting monitor server on %s", s.cfg.Listen)
	go func() {
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Printf("❌ Monitor server error: %v", err)
		}
	}()
	// Give server a moment to start and check for immediate errors
	time.Sleep(100 * time.Millisecond)
	s.logger.Printf("✅ Monitor server started on http://%s", s.cfg.Listen)

	go func() {
		<-ctx.Done()
		s.Shutdown(context.Background())
	}()
}

// Shutdown stops the server gracefully.
func (s *Server) Shutdown(ctx context.Context) {
	if s == nil || s.srv == nil {
		return
	}
	_ = s.srv.Shutdown(ctx)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.maybeSetTokenCookie(w)
	data, err := embeddedFS.ReadFile("assets/index.html")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	s.maybeSetTokenCookie(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(swaggerUIHTML))
}

func (s *Server) handleOpenAPIJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(openAPISpec())
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// 只返回初始检查通过的可用节点，同时提供完整节点列表与地域统计
	filtered := s.mgr.SnapshotFiltered(true)
	allNodes := s.mgr.Snapshot()
	totalNodes := len(allNodes)

	regionStats := make(map[string]int)
	regionHealthy := make(map[string]int)
	for _, snap := range allNodes {
		region := snap.Region
		if region == "" {
			region = "other"
		}
		regionStats[region]++
		if snap.InitialCheckDone && snap.Available && !snap.Blacklisted {
			regionHealthy[region]++
		}
	}

	payload := map[string]any{
		"nodes":          filtered,
		"all_nodes":      allNodes,
		"total_nodes":    totalNodes,
		"region_stats":   regionStats,
		"region_healthy": regionHealthy,
	}
	writeJSON(w, payload)
}

func (s *Server) handleDebug(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	snapshots := s.mgr.Snapshot()
	var totalCalls, totalSuccess int64
	debugNodes := make([]map[string]any, 0, len(snapshots))
	for _, snap := range snapshots {
		totalCalls += snap.SuccessCount + int64(snap.FailureCount)
		totalSuccess += snap.SuccessCount
		debugNodes = append(debugNodes, map[string]any{
			"tag":                snap.Tag,
			"name":               snap.Name,
			"mode":               snap.Mode,
			"port":               snap.Port,
			"failure_count":      snap.FailureCount,
			"success_count":      snap.SuccessCount,
			"active_connections": snap.ActiveConnections,
			"last_latency_ms":    snap.LastLatencyMs,
			"last_success":       snap.LastSuccess,
			"last_failure":       snap.LastFailure,
			"last_probe_at":      snap.LastProbeAt,
			"last_probe_cached":  snap.LastProbeCached,
			"last_error":         snap.LastError,
			"blacklisted":        snap.Blacklisted,
			"timeline":           snap.Timeline,
		})
	}
	var successRate float64
	if totalCalls > 0 {
		successRate = float64(totalSuccess) / float64(totalCalls) * 100
	}
	writeJSON(w, map[string]any{
		"nodes":         debugNodes,
		"total_calls":   totalCalls,
		"total_success": totalSuccess,
		"success_rate":  successRate,
		"probe_logs":    s.mgr.ProbeLogs(),
	})
}

func (s *Server) handleSubscriptions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rows, err := s.mgr.ListSubscriptionRecords(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		active := make([]any, 0, len(rows))
		for _, row := range rows {
			if row.EnabledUpdate {
				active = append(active, row)
			}
		}
		writeJSON(w, map[string]any{"subscriptions": active})
	case http.MethodPost:
		if !s.ensureNodeManager(w) {
			return
		}
		var req struct {
			SubscriptionURL string `json:"subscription_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "请求格式错误"})
			return
		}
		subURL := strings.TrimSpace(req.SubscriptionURL)
		if subURL == "" {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "订阅地址不能为空"})
			return
		}
		if err := s.nodeMgr.AddSubscription(r.Context(), subURL); err != nil {
			s.respondNodeError(w, err)
			return
		}
		writeJSON(w, map[string]any{"message": "订阅已添加"})
	case http.MethodDelete:
		if !s.ensureNodeManager(w) {
			return
		}
		subURL := strings.TrimSpace(r.URL.Query().Get("url"))
		if subURL == "" {
			var req struct {
				SubscriptionURL string `json:"subscription_url"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(w, map[string]any{"error": "请求格式错误"})
				return
			}
			subURL = strings.TrimSpace(req.SubscriptionURL)
		}
		if subURL == "" {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "订阅地址不能为空"})
			return
		}
		if err := s.nodeMgr.DeleteSubscription(r.Context(), subURL); err != nil {
			s.respondNodeError(w, err)
			return
		}
		writeJSON(w, map[string]any{"message": "订阅已删除"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleNodeEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	limit := 200
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	ipPortKey := strings.TrimSpace(r.URL.Query().Get("ip_port_key"))
	rows, err := s.mgr.ListNodeEvents(r.Context(), ipPortKey, limit)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"events": rows})
}

func (s *Server) handleCurrentNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rows, err := s.mgr.ListCurrentNodes(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"nodes": rows})
}

func (s *Server) handleNodeAction(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/nodes/"), "/")
	if len(parts) < 1 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tag := parts[0]
	if tag == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	switch action {
	case "probe":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		latency, err := s.mgr.Probe(ctx, tag)
		if err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		latencyMs := latency.Milliseconds()
		if latencyMs == 0 && latency > 0 {
			latencyMs = 1 // Round up sub-millisecond latencies to 1ms
		}
		writeJSON(w, map[string]any{"message": "探测成功", "latency_ms": latencyMs})
	case "release":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := s.mgr.Release(tag); err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"message": "已解除拉黑"})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// handleProbeAll probes all nodes in batches and returns results via SSE
func (s *Server) handleProbeAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	// Get all nodes
	snapshots := s.mgr.Snapshot()
	total := len(snapshots)
	if total == 0 {
		fmt.Fprintf(w, "data: %s\n\n", `{"type":"complete","total":0,"success":0,"failed":0}`)
		flusher.Flush()
		return
	}

	// Send start event
	fmt.Fprintf(w, "data: %s\n\n", fmt.Sprintf(`{"type":"start","total":%d}`, total))
	flusher.Flush()

	const probeStartInterval = 200 * time.Millisecond

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	type probeResult struct {
		snap      Snapshot
		latencyMs int64
		err       error
	}

	results := make(chan probeResult, total)
	var wg sync.WaitGroup
	var lastStart time.Time

launchLoop:
	for _, snap := range snapshots {
		select {
		case <-ctx.Done():
			break launchLoop
		default:
		}

		if !lastStart.IsZero() {
			delay := probeStartInterval - time.Since(lastStart)
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					break launchLoop
				}
			}
		}

		if err := s.probeSem.Acquire(ctx, 1); err != nil {
			results <- probeResult{snap: snap, latencyMs: -1, err: err}
			continue
		}

		lastStart = time.Now()
		wg.Add(1)
		go func(snap Snapshot) {
			defer wg.Done()
			defer s.probeSem.Release(1)

			probeCtx, probeCancel := context.WithTimeout(ctx, 10*time.Second)
			latency, err := s.mgr.Probe(probeCtx, snap.Tag)
			probeCancel()

			latencyMs := latency.Milliseconds()
			if latencyMs == 0 && latency > 0 {
				latencyMs = 1
			}
			if err != nil {
				latencyMs = -1
			}

			results <- probeResult{snap: snap, latencyMs: latencyMs, err: err}
		}(snap)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	successCount := 0
	failedCount := 0
	count := 0

	for result := range results {
		count++
		status := "success"
		errMsg := ""
		if result.err != nil {
			failedCount++
			status = "error"
			errMsg = result.err.Error()
		} else {
			successCount++
		}

		progress := float64(count) / float64(total) * 100
		eventData := fmt.Sprintf(`{"type":"progress","tag":"%s","name":"%s","latency":%d,"status":"%s","error":"%s","current":%d,"total":%d,"progress":%.1f}`,
			result.snap.Tag, result.snap.Name, result.latencyMs, status, errMsg, count, total, progress)
		fmt.Fprintf(w, "data: %s\n\n", eventData)
		flusher.Flush()
	}

	if ctx.Err() != nil {
		return
	}

	fmt.Fprintf(w, "data: %s\n\n", fmt.Sprintf(`{"type":"complete","total":%d,"success":%d,"failed":%d}`, total, successCount, failedCount))
	flusher.Flush()
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

func wantsJSON(r *http.Request) bool {
	if r == nil {
		return false
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "json" || format == "application/json" {
		return true
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	return strings.Contains(accept, "application/json")
}

func (s *Server) isTokenValid(token string) bool {
	if token == "" {
		return false
	}
	if s.validateSession(token) {
		return true
	}
	apiToken := strings.TrimSpace(s.cfg.APIToken)
	if apiToken != "" && token == apiToken {
		return true
	}
	return false
}

func (s *Server) isAuthorized(r *http.Request) bool {
	if r == nil {
		return false
	}
	if cookie, err := r.Cookie("session_token"); err == nil {
		if s.isTokenValid(cookie.Value) {
			return true
		}
	}
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if s.isTokenValid(token) {
			return true
		}
	}
	return false
}

func (s *Server) setTokenCookie(w http.ResponseWriter, token string, maxAge int) {
	if token == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // 生产环境应启用 HTTPS 并设为 true
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	})
}

func (s *Server) maybeSetTokenCookie(w http.ResponseWriter) {
	if s.cfg.Password != "" {
		return
	}
	apiToken := strings.TrimSpace(s.cfg.APIToken)
	if apiToken == "" {
		return
	}
	s.setTokenCookie(w, apiToken, 86400*7)
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		allowValue, ok := s.corsAllowOrigin(origin)
		if ok {
			w.Header().Set("Access-Control-Allow-Origin", allowValue)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Max-Age", "600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) corsAllowOrigin(origin string) (string, bool) {
	if strings.TrimSpace(origin) == "" {
		return "", false
	}
	s.cfgMu.RLock()
	origins := append([]string(nil), s.cfg.CORSOrigins...)
	s.cfgMu.RUnlock()
	if len(origins) == 0 {
		return "", false
	}
	for _, allowed := range origins {
		allowed = strings.TrimSpace(allowed)
		if allowed == "*" {
			return "*", true
		}
		if strings.EqualFold(allowed, origin) {
			return origin, true
		}
	}
	return "", false
}

// withAuth 认证中间件，如果配置了密码或 token 则需要验证
func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 如果没有配置密码且没有 token，直接放行
		if s.cfg.Password == "" && strings.TrimSpace(s.cfg.APIToken) == "" {
			next(w, r)
			return
		}

		if s.isAuthorized(r) {
			next(w, r)
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]any{"error": "未授权，请先登录"})
	}
}

// handleAuth 处理登录认证
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	apiToken := strings.TrimSpace(s.cfg.APIToken)

	if r.Method == http.MethodGet {
		if s.cfg.Password == "" {
			if apiToken != "" {
				s.setTokenCookie(w, apiToken, 86400*7)
			}
			writeJSON(w, map[string]any{
				"message":     "无需密码",
				"no_password": true,
				"token":       apiToken,
				"api_token":   apiToken,
			})
			return
		}
		if s.isAuthorized(r) {
			token := ""
			if cookie, err := r.Cookie("session_token"); err == nil && s.isTokenValid(cookie.Value) {
				token = cookie.Value
			}
			if token == "" {
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					candidate := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
					if s.isTokenValid(candidate) {
						token = candidate
					}
				}
			}
			writeJSON(w, map[string]any{
				"message":   "已登录",
				"token":     token,
				"api_token": apiToken,
			})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]any{"error": "未授权，请先登录"})
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if s.cfg.Password == "" {
		if apiToken != "" {
			s.setTokenCookie(w, apiToken, 86400*7)
		}
		writeJSON(w, map[string]any{
			"message":     "无需密码",
			"no_password": true,
			"token":       apiToken,
			"api_token":   apiToken,
		})
		return
	}

	var req struct {
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "请求格式错误"})
		return
	}

	// 使用 constant-time 比较防止时序攻击
	if !secureCompareStrings(req.Password, s.cfg.Password) {
		// 添加随机延迟防止暴力破解
		time.Sleep(time.Duration(100+mathrand.Intn(200)) * time.Millisecond)
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]any{"error": "密码错误"})
		return
	}

	session, err := s.createSession()
	if err != nil {
		s.logger.Printf("Failed to create session: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"error": "服务器错误"})
		return
	}

	s.setTokenCookie(w, session.Token, int(s.sessionTTL.Seconds()))

	writeJSON(w, map[string]any{
		"message":   "登录成功",
		"token":     session.Token,
		"api_token": apiToken,
	})
}

// handleExport 导出所有可用代理池节点的 HTTP 代理 URI，每行一个
// 在 hybrid 模式下，只导出 multi-port 格式（每节点独立端口）
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// 只导出初始检查通过的可用节点
	snapshots := s.mgr.SnapshotFiltered(true)
	var lines []string

	proxyUser, proxyPass := s.proxyAuth()
	for _, snap := range snapshots {
		// 只导出有监听地址和端口的节点
		if snap.ListenAddress == "" || snap.Port == 0 {
			continue
		}

		// 在 hybrid 和 multi-port 模式下，导出每节点独立端口
		// 在 pool 模式下，所有节点共享同一端口，也正常导出
		listenAddr := snap.ListenAddress
		if listenAddr == "0.0.0.0" || listenAddr == "::" {
			if extIP, _, _ := s.getSettings(); extIP != "" {
				listenAddr = extIP
			}
		}

		var proxyURI string
		if proxyUser != "" && proxyPass != "" {
			proxyURI = fmt.Sprintf("http://%s:%s@%s:%d",
				proxyUser, proxyPass,
				listenAddr, snap.Port)
		} else {
			proxyURI = fmt.Sprintf("http://%s:%d", listenAddr, snap.Port)
		}
		lines = append(lines, proxyURI)
	}

	if wantsJSON(r) {
		writeJSON(w, map[string]any{
			"count":   len(lines),
			"proxies": lines,
		})
		return
	}

	// 返回纯文本，每行一个 URI
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=proxy_pool.txt")
	_, _ = w.Write([]byte(strings.Join(lines, "\n")))
}

// handleExportFilter returns filtered proxy URIs in JSON format.
// Query params:
// - shared_min / shared_max: numeric shared user bounds
// - country: matches country/location (case-insensitive contains)
// - ip_src: matches ip_src (e.g. 原生/广播)
// - ip_attr: matches ip_attr (e.g. 住宅/机房)
// - fraud_max: max fraud score (percent)
// - pure_max: max pure score (percent)
// - latency_max: max latency (ms)
func (s *Server) handleExportFilter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()
	sharedMin, hasSharedMin := parseIntParam(query.Get("shared_min"))
	sharedMax, hasSharedMax := parseIntParam(query.Get("shared_max"))
	fraudMax, hasFraudMax := parseFloatParam(query.Get("fraud_max"))
	pureMax, hasPureMax := parseFloatParam(query.Get("pure_max"))
	latencyMax, hasLatencyMax := parseIntParam(query.Get("latency_max"))
	country := strings.TrimSpace(query.Get("country"))
	ipSrc := strings.TrimSpace(query.Get("ip_src"))
	ipAttr := strings.TrimSpace(query.Get("ip_attr"))

	// 只导出初始检查通过的可用节点
	snapshots := s.mgr.SnapshotFiltered(true)
	var proxies []string

	proxyUser, proxyPass := s.proxyAuth()
	extIP, _, _ := s.getSettings()

	for _, snap := range snapshots {
		if snap.ListenAddress == "" || snap.Port == 0 {
			continue
		}

		if !matchIPInfoFilters(snap.IPInfo, country, ipSrc, ipAttr, sharedMin, sharedMax, hasSharedMin, hasSharedMax) {
			continue
		}
		if hasLatencyMax {
			if snap.LastLatencyMs < 0 || int(snap.LastLatencyMs) > latencyMax {
				continue
			}
		}
		if !matchScoreFilters(snap.IPInfo, pureMax, fraudMax, hasPureMax, hasFraudMax) {
			continue
		}

		listenAddr := snap.ListenAddress
		if listenAddr == "0.0.0.0" || listenAddr == "::" {
			if extIP != "" {
				listenAddr = extIP
			}
		}

		var proxyURI string
		if proxyUser != "" && proxyPass != "" {
			proxyURI = fmt.Sprintf("http://%s:%s@%s:%d",
				proxyUser, proxyPass,
				listenAddr, snap.Port)
		} else {
			proxyURI = fmt.Sprintf("http://%s:%d", listenAddr, snap.Port)
		}
		proxies = append(proxies, proxyURI)
	}

	writeJSON(w, map[string]any{
		"count":   len(proxies),
		"proxies": proxies,
	})
}

func parseIntParam(value string) (int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	return n, true
}

func parseFloatParam(value string) (float64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	n, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func parseSharedCount(value string) (int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	nums := make([]int, 0, 2)
	cur := 0
	inNum := false
	for _, r := range value {
		if r >= '0' && r <= '9' {
			cur = cur*10 + int(r-'0')
			inNum = true
			continue
		}
		if inNum {
			nums = append(nums, cur)
			cur = 0
			inNum = false
		}
	}
	if inNum {
		nums = append(nums, cur)
	}
	if len(nums) == 0 {
		return 0, false
	}
	upper := nums[len(nums)-1]
	if strings.Contains(value, "+") {
		upper++
	}
	return upper, true
}

func parsePercentValue(value string) (float64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	value = strings.TrimSuffix(value, "%")
	n, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func matchIPInfoFilters(info *IPInfo, country, ipSrc, ipAttr string, sharedMin, sharedMax int, hasSharedMin, hasSharedMax bool) bool {
	hasFilter := country != "" || ipSrc != "" || ipAttr != "" || hasSharedMin || hasSharedMax
	if info == nil {
		return !hasFilter
	}

	if country != "" {
		if !containsFold(info.Country, country) && !containsFold(info.Location, country) {
			return false
		}
	}
	if ipSrc != "" && !containsFold(info.IPSrc, ipSrc) {
		return false
	}
	if ipAttr != "" && !containsFold(info.IPAttr, ipAttr) {
		return false
	}

	if hasSharedMin || hasSharedMax {
		sharedCount, ok := parseSharedCount(info.SharedUsers)
		if !ok {
			return false
		}
		if hasSharedMin && sharedCount < sharedMin {
			return false
		}
		if hasSharedMax && sharedCount > sharedMax {
			return false
		}
	}

	return true
}

func matchScoreFilters(info *IPInfo, pureMax, fraudMax float64, hasPureMax, hasFraudMax bool) bool {
	if !hasPureMax && !hasFraudMax {
		return true
	}
	if info == nil {
		return false
	}
	if hasPureMax {
		pureVal, ok := parsePercentValue(info.PureScore)
		if !ok || pureVal > pureMax {
			return false
		}
	}
	if hasFraudMax {
		fraudVal, ok := parsePercentValue(info.FraudScore)
		if !ok || fraudVal > fraudMax {
			return false
		}
	}
	return true
}

func containsFold(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

// handleSettings handles GET/PUT for dynamic settings (external_ip, probe_target, skip_cert_verify).
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		extIP, probeTarget, skipCertVerify := s.getSettings()
		proxyUser, proxyPass := s.proxyAuth()
		writeJSON(w, map[string]any{
			"external_ip":      extIP,
			"probe_target":     probeTarget,
			"skip_cert_verify": skipCertVerify,
			"proxy_username":   proxyUser,
			"proxy_password":   proxyPass,
			"api_token":        s.cfg.APIToken,
		})
	case http.MethodPut:
		var req struct {
			ExternalIP     string `json:"external_ip"`
			ProbeTarget    string `json:"probe_target"`
			SkipCertVerify bool   `json:"skip_cert_verify"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "请求格式错误"})
			return
		}

		extIP := strings.TrimSpace(req.ExternalIP)
		probeTarget := strings.TrimSpace(req.ProbeTarget)

		if err := s.updateSettings(extIP, probeTarget, req.SkipCertVerify); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}

		writeJSON(w, map[string]any{
			"message":          "设置已保存",
			"external_ip":      extIP,
			"probe_target":     probeTarget,
			"skip_cert_verify": req.SkipCertVerify,
			"need_reload":      true,
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleSubscriptionStatus returns the current subscription refresh status.
func (s *Server) handleSubscriptionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if s.subRefresher == nil {
		writeJSON(w, map[string]any{
			"enabled": false,
			"message": "订阅刷新未启用",
		})
		return
	}

	status := s.subRefresher.Status()
	writeJSON(w, map[string]any{
		"enabled":          true,
		"last_refresh":     status.LastRefresh,
		"next_refresh":     status.NextRefresh,
		"node_count":       status.NodeCount,
		"last_error":       status.LastError,
		"refresh_count":    status.RefreshCount,
		"is_refreshing":    status.IsRefreshing,
		"nodes_modified":   status.NodesModified,
		"progress_total":   status.ProgressTotal,
		"progress_current": status.ProgressCurrent,
		"progress_nodes":   status.ProgressNodes,
		"progress_message": status.ProgressMessage,
	})
}

// handleSubscriptionRefresh triggers an immediate subscription refresh.
func (s *Server) handleSubscriptionRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if s.subRefresher == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]any{"error": "订阅刷新未启用"})
		return
	}

	if err := s.subRefresher.RefreshNow(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}

	status := s.subRefresher.Status()
	writeJSON(w, map[string]any{
		"message":    "刷新成功",
		"node_count": status.NodeCount,
	})
}

// nodePayload is the JSON request body for node CRUD operations.
type nodePayload struct {
	Name     string `json:"name"`
	URI      string `json:"uri"`
	Port     uint16 `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (p nodePayload) toConfig() config.NodeConfig {
	return config.NodeConfig{
		Name:     p.Name,
		URI:      p.URI,
		Port:     p.Port,
		Username: p.Username,
		Password: p.Password,
	}
}

// handleConfigNodes handles GET (list) and POST (create) for config nodes.
func (s *Server) handleConfigNodes(w http.ResponseWriter, r *http.Request) {
	if !s.ensureNodeManager(w) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		nodes, err := s.nodeMgr.ListConfigNodes(r.Context())
		if err != nil {
			s.respondNodeError(w, err)
			return
		}
		writeJSON(w, map[string]any{"nodes": nodes})
	case http.MethodPost:
		var payload nodePayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "请求格式错误"})
			return
		}
		node, err := s.nodeMgr.CreateNode(r.Context(), payload.toConfig())
		if err != nil {
			s.respondNodeError(w, err)
			return
		}
		writeJSON(w, map[string]any{"node": node, "message": "节点已添加，请点击重载使配置生效"})
	case http.MethodDelete:
		if err := s.nodeMgr.DeleteAllNodes(r.Context()); err != nil {
			s.respondNodeError(w, err)
			return
		}
		writeJSON(w, map[string]any{"message": "所有节点已删除，请点击重载使配置生效"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleConfigNodeItem handles PUT (update) and DELETE for a specific config node.
func (s *Server) handleConfigNodeItem(w http.ResponseWriter, r *http.Request) {
	if !s.ensureNodeManager(w) {
		return
	}

	namePart := strings.TrimPrefix(r.URL.Path, "/api/nodes/config/")
	nodeName, err := url.PathUnescape(namePart)
	if err != nil || nodeName == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "节点名称无效"})
		return
	}

	switch r.Method {
	case http.MethodPut:
		var payload nodePayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "请求格式错误"})
			return
		}
		node, err := s.nodeMgr.UpdateNode(r.Context(), nodeName, payload.toConfig())
		if err != nil {
			s.respondNodeError(w, err)
			return
		}
		writeJSON(w, map[string]any{"node": node, "message": "节点已更新，请点击重载使配置生效"})
	case http.MethodDelete:
		if err := s.nodeMgr.DeleteNode(r.Context(), nodeName); err != nil {
			s.respondNodeError(w, err)
			return
		}
		writeJSON(w, map[string]any{"message": "节点已删除，请点击重载使配置生效"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleReload triggers a configuration reload.
func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.ensureNodeManager(w) {
		return
	}

	if err := s.nodeMgr.TriggerReload(r.Context()); err != nil {
		s.respondNodeError(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"message": "重载成功，现有连接已被中断",
	})
}

func (s *Server) ensureNodeManager(w http.ResponseWriter) bool {
	if s.nodeMgr == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]any{"error": "节点管理未启用"})
		return false
	}
	return true
}

func (s *Server) respondNodeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrNodeNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ErrSubscriptionNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ErrNodeConflict), errors.Is(err, ErrInvalidNode), errors.Is(err, ErrSubscriptionConflict), errors.Is(err, ErrInvalidSubscription):
		status = http.StatusBadRequest
	}
	w.WriteHeader(status)
	writeJSON(w, map[string]any{"error": err.Error()})
}

// Session management functions

// generateSessionToken creates a cryptographically secure random token.
func (s *Server) generateSessionToken() (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate session token: %w", err)
	}
	return hex.EncodeToString(tokenBytes), nil
}

// createSession creates a new session with expiration.
func (s *Server) createSession() (*Session, error) {
	token, err := s.generateSessionToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	session := &Session{
		Token:     token,
		CreatedAt: now,
		ExpiresAt: now.Add(s.sessionTTL),
	}

	s.sessionMu.Lock()
	s.sessions[token] = session
	s.sessionMu.Unlock()

	return session, nil
}

// validateSession checks if a session token is valid and not expired.
func (s *Server) validateSession(token string) bool {
	s.sessionMu.RLock()
	session, exists := s.sessions[token]
	s.sessionMu.RUnlock()

	if !exists {
		return false
	}

	// Check if expired
	if time.Now().After(session.ExpiresAt) {
		s.sessionMu.Lock()
		delete(s.sessions, token)
		s.sessionMu.Unlock()
		return false
	}

	return true
}

// cleanupExpiredSessions periodically removes expired sessions.
func (s *Server) cleanupExpiredSessions() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		s.sessionMu.Lock()
		for token, session := range s.sessions {
			if now.After(session.ExpiresAt) {
				delete(s.sessions, token)
			}
		}
		s.sessionMu.Unlock()
		s.cleanupExpiredExtractorLinks(now)
	}
}

func newRandomHex(size int) string {
	if size <= 0 {
		return ""
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return hex.EncodeToString(buf)
}

// secureCompareStrings performs constant-time string comparison to prevent timing attacks.
func secureCompareStrings(a, b string) bool {
	aBytes := []byte(a)
	bBytes := []byte(b)

	// If lengths differ, still perform a dummy comparison to maintain constant time
	if len(aBytes) != len(bBytes) {
		dummy := make([]byte, 32)
		subtle.ConstantTimeCompare(dummy, dummy)
		return false
	}

	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1
}
