package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	defaultRetention      = 30 * 24 * time.Hour
	availabilityUnknown   = -1
	availabilityUnhealthy = 0
	availabilityHealthy   = 1
)

// SubscriptionRecord stores subscription metadata (table: subscriptions).
type SubscriptionRecord struct {
	ID               int64      `json:"id"`
	Name             string     `json:"name"`
	SubscriptionURL  string     `json:"subscription_url"`
	EnabledUpdate    bool       `json:"enabled_update"`
	IntervalSeconds  int64      `json:"interval_seconds"`
	Collector        string     `json:"collector"`
	Parser           string     `json:"parser"`
	Normalized       bool       `json:"normalized"`
	UnifiedStructure bool       `json:"unified_structure"`
	Deduped          bool       `json:"deduped"`
	LastNodeCount    int        `json:"last_node_count"`
	LastFetchAt      *time.Time `json:"last_fetch_at,omitempty"`
	LastError        string     `json:"last_error,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// CurrentNode stores normalized current node data (table: current_nodes).
type CurrentNode struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	URI           string    `json:"uri"`
	Source        string    `json:"source"`
	Protocol      string    `json:"protocol"`
	ListenAddr    string    `json:"listen_addr,omitempty"`
	ListenPort    uint16    `json:"listen_port,omitempty"`
	Username      string    `json:"username,omitempty"`
	Password      string    `json:"password,omitempty"`
	IP            string    `json:"ip,omitempty"`
	LatencyMs     int64     `json:"latency_ms"`
	HealthScore   float64   `json:"health_score"`
	Availability  int       `json:"availability"` // -1 unknown, 0 fail, 1 healthy
	PureScore     string    `json:"pure_score,omitempty"`
	FraudScore    string    `json:"fraud_score,omitempty"`
	BotScore      string    `json:"bot_score,omitempty"`
	SharedUsers   string    `json:"shared_users,omitempty"`
	IPType        string    `json:"ip_type,omitempty"`
	NativeIP      string    `json:"native_ip,omitempty"`
	Country       string    `json:"country,omitempty"`
	City          string    `json:"city,omitempty"`
	Location      string    `json:"location,omitempty"`
	ISP           string    `json:"isp,omitempty"`
	ASN           int64     `json:"asn,omitempty"`
	InfoSource    string    `json:"info_source,omitempty"`
	IPPortKey     string    `json:"ip_port_key,omitempty"`
	ErrorMessage  string    `json:"error_message,omitempty"`
	Active        bool      `json:"active"`
	FirstSeenAt   time.Time `json:"first_seen_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	LastUpdatedAt time.Time `json:"last_updated_at"`
	LastCheckAt   time.Time `json:"last_check_at"`
}

// ProbeUpdate stores probe result update payload.
type ProbeUpdate struct {
	URI          string
	Name         string
	ListenAddr   string
	ListenPort   uint16
	LatencyMs    int64
	Success      bool
	ErrorMessage string
	CheckedAt    time.Time
	EventSource  string
}

// IPInfoUpdate stores ip quality update payload.
type IPInfoUpdate struct {
	URI         string
	Name        string
	ListenPort  uint16
	IP          string
	PureScore   string
	FraudScore  string
	BotScore    string
	SharedUsers string
	IPType      string
	NativeIP    string
	Country     string
	City        string
	Location    string
	ISP         string
	ASN         int64
	InfoSource  string
	UpdatedAt   time.Time
}

// NodeEvent stores event log rows (table: node_events).
type NodeEvent struct {
	ID           int64     `json:"id"`
	URI          string    `json:"uri"`
	Name         string    `json:"name"`
	IPPortKey    string    `json:"ip_port_key"`
	EventType    string    `json:"event_type"`
	EventSource  string    `json:"event_source"`
	Success      bool      `json:"success"`
	LatencyMs    int64     `json:"latency_ms"`
	ErrorMessage string    `json:"error_message,omitempty"`
	Payload      string    `json:"payload,omitempty"`
	EventAt      time.Time `json:"event_at"`
}

// Store wraps sqlite operations.
type Store struct {
	db        *sql.DB
	path      string
	retention time.Duration

	cleanupMu   sync.Mutex
	lastCleanup time.Time
}

// Open creates or opens sqlite store and ensures schema exists.
func Open(path string) (*Store, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("sqlite path is empty")
	}
	if !filepath.IsAbs(path) {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolve sqlite path: %w", err)
		}
		path = abs
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create sqlite dir: %w", err)
	}

	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", filepath.ToSlash(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	s := &Store{db: db, path: path, retention: defaultRetention}
	if err := s.initSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.PurgeOldEvents(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Path returns sqlite absolute path.
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Close closes database connections.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) initSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite store is not initialized")
	}

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS subscriptions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			subscription_url TEXT NOT NULL UNIQUE,
			enabled_update INTEGER NOT NULL DEFAULT 0,
			interval_seconds INTEGER NOT NULL DEFAULT 0,
			collector TEXT NOT NULL DEFAULT 'http',
			parser TEXT NOT NULL DEFAULT 'auto',
			normalized INTEGER NOT NULL DEFAULT 1,
			unified_structure INTEGER NOT NULL DEFAULT 1,
			deduped INTEGER NOT NULL DEFAULT 1,
			last_node_count INTEGER NOT NULL DEFAULT 0,
			last_fetch_at TEXT NOT NULL DEFAULT '',
			last_error TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_subscriptions_enabled ON subscriptions(enabled_update);`,

		`CREATE TABLE IF NOT EXISTS current_nodes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_name TEXT NOT NULL,
			node_uri TEXT NOT NULL UNIQUE,
			node_source TEXT NOT NULL DEFAULT 'subscription',
			protocol TEXT NOT NULL DEFAULT '',
			listen_address TEXT NOT NULL DEFAULT '',
			listen_port INTEGER NOT NULL DEFAULT 0,
			username TEXT NOT NULL DEFAULT '',
			password TEXT NOT NULL DEFAULT '',
			first_seen_at TEXT NOT NULL,
			last_seen_at TEXT NOT NULL,
			last_updated_at TEXT NOT NULL,
			last_check_at TEXT NOT NULL DEFAULT '',
			ip TEXT NOT NULL DEFAULT '',
			latency_ms INTEGER NOT NULL DEFAULT -1,
			health_score REAL NOT NULL DEFAULT -1,
			availability INTEGER NOT NULL DEFAULT -1,
			pure_score TEXT NOT NULL DEFAULT '',
			fraud_score TEXT NOT NULL DEFAULT '',
			bot_score TEXT NOT NULL DEFAULT '',
			shared_users TEXT NOT NULL DEFAULT '',
			ip_type TEXT NOT NULL DEFAULT '',
			native_ip TEXT NOT NULL DEFAULT '',
			country TEXT NOT NULL DEFAULT '',
			city TEXT NOT NULL DEFAULT '',
			location TEXT NOT NULL DEFAULT '',
			isp TEXT NOT NULL DEFAULT '',
			asn INTEGER NOT NULL DEFAULT 0,
			info_source TEXT NOT NULL DEFAULT '',
			ip_port_key TEXT NOT NULL DEFAULT '',
			error_message TEXT NOT NULL DEFAULT '',
			is_active INTEGER NOT NULL DEFAULT 1
		);`,
		`CREATE INDEX IF NOT EXISTS idx_current_nodes_active ON current_nodes(is_active);`,
		`CREATE INDEX IF NOT EXISTS idx_current_nodes_ip_port_key ON current_nodes(ip_port_key);`,
		`CREATE INDEX IF NOT EXISTS idx_current_nodes_source ON current_nodes(node_source);`,

		`CREATE TABLE IF NOT EXISTS node_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_uri TEXT NOT NULL,
			node_name TEXT NOT NULL DEFAULT '',
			ip_port_key TEXT NOT NULL DEFAULT '',
			event_type TEXT NOT NULL,
			event_source TEXT NOT NULL DEFAULT '',
			success INTEGER NOT NULL DEFAULT 0,
			latency_ms INTEGER NOT NULL DEFAULT -1,
			error_message TEXT NOT NULL DEFAULT '',
			event_payload TEXT NOT NULL DEFAULT '',
			event_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_node_events_at ON node_events(event_at);`,
		`CREATE INDEX IF NOT EXISTS idx_node_events_ip_port_key ON node_events(ip_port_key);`,
		`CREATE INDEX IF NOT EXISTS idx_node_events_uri ON node_events(node_uri);`,
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schema tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("exec schema: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schema tx: %w", err)
	}
	return nil
}

// UpsertSubscriptions writes table1 configuration rows.
func (s *Store) UpsertSubscriptions(ctx context.Context, records []SubscriptionRecord) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite store is not initialized")
	}

	uniq := make(map[string]SubscriptionRecord, len(records))
	for _, rec := range records {
		urlVal := strings.TrimSpace(rec.SubscriptionURL)
		if urlVal == "" {
			continue
		}
		rec.SubscriptionURL = urlVal
		if strings.TrimSpace(rec.Name) == "" {
			rec.Name = subscriptionNameFromURL(urlVal)
		}
		if strings.TrimSpace(rec.Collector) == "" {
			rec.Collector = "http"
		}
		if strings.TrimSpace(rec.Parser) == "" {
			rec.Parser = "auto"
		}
		if rec.IntervalSeconds < 0 {
			rec.IntervalSeconds = 0
		}
		uniq[urlVal] = rec
	}

	urls := make([]string, 0, len(uniq))
	for k := range uniq {
		urls = append(urls, k)
	}
	sort.Strings(urls)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin upsert subscriptions tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339)
	for _, urlVal := range urls {
		rec := uniq[urlVal]
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO subscriptions (
				name, subscription_url, enabled_update, interval_seconds,
				collector, parser, normalized, unified_structure, deduped,
				last_node_count, last_fetch_at, last_error, created_at, updated_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(subscription_url) DO UPDATE SET
				name=excluded.name,
				enabled_update=excluded.enabled_update,
				interval_seconds=excluded.interval_seconds,
				collector=excluded.collector,
				parser=excluded.parser,
				normalized=excluded.normalized,
				unified_structure=excluded.unified_structure,
				deduped=excluded.deduped,
				updated_at=excluded.updated_at;
		`,
			rec.Name,
			rec.SubscriptionURL,
			boolToInt(rec.EnabledUpdate),
			rec.IntervalSeconds,
			rec.Collector,
			rec.Parser,
			boolToInt(rec.Normalized),
			boolToInt(rec.UnifiedStructure),
			boolToInt(rec.Deduped),
			rec.LastNodeCount,
			timeToText(rec.LastFetchAt),
			strings.TrimSpace(rec.LastError),
			now,
			now,
		); err != nil {
			return fmt.Errorf("upsert subscription %s: %w", urlVal, err)
		}
	}

	if len(urls) == 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE subscriptions SET enabled_update=0, updated_at=?`, now); err != nil {
			return fmt.Errorf("disable all subscriptions: %w", err)
		}
	} else {
		args := make([]any, 0, len(urls)+1)
		args = append(args, now)
		for _, u := range urls {
			args = append(args, u)
		}
		q := fmt.Sprintf(`UPDATE subscriptions SET enabled_update=0, updated_at=? WHERE subscription_url NOT IN (%s)`, placeholders(len(urls)))
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			return fmt.Errorf("disable removed subscriptions: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit upsert subscriptions tx: %w", err)
	}
	return nil
}

// MarkSubscriptionFetchResult updates fetch status in table1.
func (s *Store) MarkSubscriptionFetchResult(ctx context.Context, subURL string, nodeCount int, errMessage string, fetchedAt time.Time) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite store is not initialized")
	}
	subURL = strings.TrimSpace(subURL)
	if subURL == "" {
		return nil
	}
	now := nowUTC(fetchedAt).Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO subscriptions (
			name, subscription_url, enabled_update, interval_seconds,
			collector, parser, normalized, unified_structure, deduped,
			last_node_count, last_fetch_at, last_error, created_at, updated_at
		)
		VALUES (?, ?, 1, 0, 'http', 'auto', 1, 1, 1, ?, ?, ?, ?, ?)
		ON CONFLICT(subscription_url) DO UPDATE SET
			last_node_count=excluded.last_node_count,
			last_fetch_at=excluded.last_fetch_at,
			last_error=excluded.last_error,
			updated_at=excluded.updated_at;
	`,
		subscriptionNameFromURL(subURL),
		subURL,
		nodeCount,
		now,
		strings.TrimSpace(errMessage),
		now,
		now,
	)
	if err != nil {
		return fmt.Errorf("mark subscription fetch result: %w", err)
	}
	return nil
}

// ListSubscriptions reads table1.
func (s *Store) ListSubscriptions(ctx context.Context) ([]SubscriptionRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("sqlite store is not initialized")
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, subscription_url, enabled_update, interval_seconds,
			collector, parser, normalized, unified_structure, deduped,
			last_node_count, last_fetch_at, last_error, created_at, updated_at
		FROM subscriptions
		ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query subscriptions: %w", err)
	}
	defer rows.Close()

	out := make([]SubscriptionRecord, 0)
	for rows.Next() {
		var rec SubscriptionRecord
		var enabled, normalized, unified, deduped int
		var lastFetch, createdAt, updatedAt string
		if err := rows.Scan(
			&rec.ID,
			&rec.Name,
			&rec.SubscriptionURL,
			&enabled,
			&rec.IntervalSeconds,
			&rec.Collector,
			&rec.Parser,
			&normalized,
			&unified,
			&deduped,
			&rec.LastNodeCount,
			&lastFetch,
			&rec.LastError,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan subscriptions: %w", err)
		}
		rec.EnabledUpdate = enabled == 1
		rec.Normalized = normalized == 1
		rec.UnifiedStructure = unified == 1
		rec.Deduped = deduped == 1
		if t, ok := parseTime(lastFetch); ok {
			rec.LastFetchAt = &t
		}
		if t, ok := parseTime(createdAt); ok {
			rec.CreatedAt = t
		}
		if t, ok := parseTime(updatedAt); ok {
			rec.UpdatedAt = t
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subscriptions: %w", err)
	}
	return out, nil
}

// ReplaceAllCurrentNodes upserts nodes to table2 and deactivates removed nodes.
func (s *Store) ReplaceAllCurrentNodes(ctx context.Context, nodes []CurrentNode) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite store is not initialized")
	}

	deduped := dedupeCurrentNodes(nodes)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin replace current nodes tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	nowText := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.ExecContext(ctx, `UPDATE current_nodes SET is_active=0, last_updated_at=?`, nowText); err != nil {
		return fmt.Errorf("deactivate existing current nodes: %w", err)
	}

	for _, node := range deduped {
		if err := upsertCurrentNodeTx(ctx, tx, node, true); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit replace current nodes tx: %w", err)
	}
	return nil
}

// LoadActiveNodes reads active current nodes from table2.
func (s *Store) LoadActiveNodes(ctx context.Context) ([]CurrentNode, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("sqlite store is not initialized")
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, node_name, node_uri, node_source, protocol,
			listen_address, listen_port, username, password,
			ip, latency_ms, health_score, availability,
			pure_score, fraud_score, bot_score, shared_users, ip_type, native_ip,
			country, city, location, isp, asn, info_source, ip_port_key, error_message,
			is_active, first_seen_at, last_seen_at, last_updated_at, last_check_at
		FROM current_nodes
		WHERE is_active=1
		ORDER BY node_name ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query active current nodes: %w", err)
	}
	defer rows.Close()

	out := make([]CurrentNode, 0)
	for rows.Next() {
		var n CurrentNode
		var port int
		var active int
		var firstSeen, lastSeen, lastUpdated, lastCheck string
		if err := rows.Scan(
			&n.ID,
			&n.Name,
			&n.URI,
			&n.Source,
			&n.Protocol,
			&n.ListenAddr,
			&port,
			&n.Username,
			&n.Password,
			&n.IP,
			&n.LatencyMs,
			&n.HealthScore,
			&n.Availability,
			&n.PureScore,
			&n.FraudScore,
			&n.BotScore,
			&n.SharedUsers,
			&n.IPType,
			&n.NativeIP,
			&n.Country,
			&n.City,
			&n.Location,
			&n.ISP,
			&n.ASN,
			&n.InfoSource,
			&n.IPPortKey,
			&n.ErrorMessage,
			&active,
			&firstSeen,
			&lastSeen,
			&lastUpdated,
			&lastCheck,
		); err != nil {
			return nil, fmt.Errorf("scan active current nodes: %w", err)
		}
		n.ListenPort = intToPort(port)
		n.Active = active == 1
		n.FirstSeenAt, _ = parseTime(firstSeen)
		n.LastSeenAt, _ = parseTime(lastSeen)
		n.LastUpdatedAt, _ = parseTime(lastUpdated)
		n.LastCheckAt, _ = parseTime(lastCheck)
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active current nodes: %w", err)
	}
	return out, nil
}

// UpdateProbeResult updates table2 probe fields and appends table3 probe event.
func (s *Store) UpdateProbeResult(ctx context.Context, upd ProbeUpdate) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite store is not initialized")
	}
	upd.URI = strings.TrimSpace(upd.URI)
	if upd.URI == "" {
		return nil
	}

	checkedAt := nowUTC(upd.CheckedAt)
	latency := upd.LatencyMs
	if latency < 0 {
		latency = -1
	}
	availability := availabilityUnhealthy
	if upd.Success {
		availability = availabilityHealthy
	}
	healthScore := calcHealthScore(upd.Success, latency)
	nowText := checkedAt.Format(time.RFC3339)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO current_nodes (
			node_name, node_uri, node_source, protocol,
			listen_address, listen_port, username, password,
			first_seen_at, last_seen_at, last_updated_at, last_check_at,
			ip, latency_ms, health_score, availability,
			pure_score, fraud_score, bot_score, shared_users,
			ip_type, native_ip, country, city, location, isp, asn, info_source,
			ip_port_key, error_message, is_active
		)
		VALUES (?, ?, 'runtime', ?, ?, ?, '', '', ?, ?, ?, ?, '', ?, ?, ?, '', '', '', '', '', '', '', '', '', '', 0, ?, '', ?, 1)
		ON CONFLICT(node_uri) DO UPDATE SET
			node_name=CASE WHEN excluded.node_name != '' THEN excluded.node_name ELSE current_nodes.node_name END,
			protocol=CASE WHEN excluded.protocol != '' THEN excluded.protocol ELSE current_nodes.protocol END,
			listen_address=CASE WHEN excluded.listen_address != '' THEN excluded.listen_address ELSE current_nodes.listen_address END,
			listen_port=CASE WHEN excluded.listen_port > 0 THEN excluded.listen_port ELSE current_nodes.listen_port END,
			last_seen_at=excluded.last_seen_at,
			last_updated_at=excluded.last_updated_at,
			last_check_at=excluded.last_check_at,
			latency_ms=excluded.latency_ms,
			health_score=excluded.health_score,
			availability=excluded.availability,
			error_message=excluded.error_message,
			is_active=1;
	`,
		strings.TrimSpace(upd.Name),
		upd.URI,
		parseProtocol(upd.URI),
		strings.TrimSpace(upd.ListenAddr),
		int(upd.ListenPort),
		nowText,
		nowText,
		nowText,
		nowText,
		latency,
		healthScore,
		availability,
		strings.TrimSpace(upd.EventSource),
		strings.TrimSpace(upd.ErrorMessage),
	)
	if err != nil {
		return fmt.Errorf("update probe result: %w", err)
	}

	key, _ := s.ResolveIPPortKey(ctx, upd.URI, upd.ListenPort)
	event := NodeEvent{
		URI:          upd.URI,
		Name:         strings.TrimSpace(upd.Name),
		IPPortKey:    key,
		EventType:    "probe",
		EventSource:  strings.TrimSpace(upd.EventSource),
		Success:      upd.Success,
		LatencyMs:    latency,
		ErrorMessage: strings.TrimSpace(upd.ErrorMessage),
		EventAt:      checkedAt,
	}
	if event.EventSource == "" {
		event.EventSource = "manual"
	}
	return s.AppendNodeEvent(ctx, event)
}

// UpdateNodeIPInfo updates table2 ip quality fields and appends table3 event.
func (s *Store) UpdateNodeIPInfo(ctx context.Context, upd IPInfoUpdate) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite store is not initialized")
	}
	upd.URI = strings.TrimSpace(upd.URI)
	if upd.URI == "" {
		return nil
	}

	updatedAt := nowUTC(upd.UpdatedAt)
	updatedText := updatedAt.Format(time.RFC3339)
	ipPortKey := BuildIPPortKey(upd.IP, upd.ListenPort)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO current_nodes (
			node_name, node_uri, node_source, protocol,
			listen_address, listen_port, username, password,
			first_seen_at, last_seen_at, last_updated_at, last_check_at,
			ip, latency_ms, health_score, availability,
			pure_score, fraud_score, bot_score, shared_users,
			ip_type, native_ip, country, city, location, isp, asn, info_source,
			ip_port_key, error_message, is_active
		)
		VALUES (?, ?, 'runtime', ?, '', ?, '', '', ?, ?, ?, ?, ?, -1, -1, -1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', 1)
		ON CONFLICT(node_uri) DO UPDATE SET
			node_name=CASE WHEN excluded.node_name != '' THEN excluded.node_name ELSE current_nodes.node_name END,
			listen_port=CASE WHEN excluded.listen_port > 0 THEN excluded.listen_port ELSE current_nodes.listen_port END,
			last_seen_at=excluded.last_seen_at,
			last_updated_at=excluded.last_updated_at,
			last_check_at=excluded.last_check_at,
			ip=CASE WHEN excluded.ip != '' THEN excluded.ip ELSE current_nodes.ip END,
			pure_score=CASE WHEN excluded.pure_score != '' THEN excluded.pure_score ELSE current_nodes.pure_score END,
			fraud_score=CASE WHEN excluded.fraud_score != '' THEN excluded.fraud_score ELSE current_nodes.fraud_score END,
			bot_score=CASE WHEN excluded.bot_score != '' THEN excluded.bot_score ELSE current_nodes.bot_score END,
			shared_users=CASE WHEN excluded.shared_users != '' THEN excluded.shared_users ELSE current_nodes.shared_users END,
			ip_type=CASE WHEN excluded.ip_type != '' THEN excluded.ip_type ELSE current_nodes.ip_type END,
			native_ip=CASE WHEN excluded.native_ip != '' THEN excluded.native_ip ELSE current_nodes.native_ip END,
			country=CASE WHEN excluded.country != '' THEN excluded.country ELSE current_nodes.country END,
			city=CASE WHEN excluded.city != '' THEN excluded.city ELSE current_nodes.city END,
			location=CASE WHEN excluded.location != '' THEN excluded.location ELSE current_nodes.location END,
			isp=CASE WHEN excluded.isp != '' THEN excluded.isp ELSE current_nodes.isp END,
			asn=CASE WHEN excluded.asn > 0 THEN excluded.asn ELSE current_nodes.asn END,
			info_source=CASE WHEN excluded.info_source != '' THEN excluded.info_source ELSE current_nodes.info_source END,
			ip_port_key=CASE WHEN excluded.ip_port_key != '' THEN excluded.ip_port_key ELSE current_nodes.ip_port_key END,
			is_active=1;
	`,
		strings.TrimSpace(upd.Name),
		upd.URI,
		parseProtocol(upd.URI),
		int(upd.ListenPort),
		updatedText,
		updatedText,
		updatedText,
		updatedText,
		strings.TrimSpace(upd.IP),
		strings.TrimSpace(upd.PureScore),
		strings.TrimSpace(upd.FraudScore),
		strings.TrimSpace(upd.BotScore),
		strings.TrimSpace(upd.SharedUsers),
		strings.TrimSpace(upd.IPType),
		strings.TrimSpace(upd.NativeIP),
		strings.TrimSpace(upd.Country),
		strings.TrimSpace(upd.City),
		strings.TrimSpace(upd.Location),
		strings.TrimSpace(upd.ISP),
		upd.ASN,
		strings.TrimSpace(upd.InfoSource),
		ipPortKey,
	)
	if err != nil {
		return fmt.Errorf("update node ip info: %w", err)
	}

	event := NodeEvent{
		URI:         upd.URI,
		Name:        strings.TrimSpace(upd.Name),
		IPPortKey:   ipPortKey,
		EventType:   "ip_info",
		EventSource: strings.TrimSpace(upd.InfoSource),
		Success:     true,
		LatencyMs:   -1,
		EventAt:     updatedAt,
	}
	if event.EventSource == "" {
		event.EventSource = "unknown"
	}
	return s.AppendNodeEvent(ctx, event)
}

// AppendNodeEvent writes one row into table3 and runs periodic retention cleanup.
func (s *Store) AppendNodeEvent(ctx context.Context, event NodeEvent) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite store is not initialized")
	}
	event.URI = strings.TrimSpace(event.URI)
	if event.URI == "" {
		return nil
	}
	if event.EventAt.IsZero() {
		event.EventAt = time.Now().UTC()
	}
	if strings.TrimSpace(event.EventType) == "" {
		event.EventType = "event"
	}
	if strings.TrimSpace(event.IPPortKey) == "" {
		if key, err := s.ResolveIPPortKey(ctx, event.URI, 0); err == nil {
			event.IPPortKey = key
		}
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO node_events (
			node_uri, node_name, ip_port_key,
			event_type, event_source, success,
			latency_ms, error_message, event_payload, event_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		event.URI,
		strings.TrimSpace(event.Name),
		strings.TrimSpace(event.IPPortKey),
		strings.TrimSpace(event.EventType),
		strings.TrimSpace(event.EventSource),
		boolToInt(event.Success),
		event.LatencyMs,
		strings.TrimSpace(event.ErrorMessage),
		strings.TrimSpace(event.Payload),
		event.EventAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("insert node event: %w", err)
	}

	s.maybePurgeOldEvents(ctx)
	return nil
}

// ListNodeEvents reads table3 ordered by newest first.
func (s *Store) ListNodeEvents(ctx context.Context, ipPortKey string, limit int) ([]NodeEvent, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("sqlite store is not initialized")
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}

	ipPortKey = strings.TrimSpace(ipPortKey)
	var (
		rows *sql.Rows
		err  error
	)
	if ipPortKey == "" {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, node_uri, node_name, ip_port_key, event_type, event_source,
				success, latency_ms, error_message, event_payload, event_at
			FROM node_events
			ORDER BY event_at DESC, id DESC
			LIMIT ?`, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, node_uri, node_name, ip_port_key, event_type, event_source,
				success, latency_ms, error_message, event_payload, event_at
			FROM node_events
			WHERE ip_port_key = ?
			ORDER BY event_at DESC, id DESC
			LIMIT ?`, ipPortKey, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("query node events: %w", err)
	}
	defer rows.Close()

	out := make([]NodeEvent, 0)
	for rows.Next() {
		var ev NodeEvent
		var success int
		var eventAt string
		if err := rows.Scan(
			&ev.ID,
			&ev.URI,
			&ev.Name,
			&ev.IPPortKey,
			&ev.EventType,
			&ev.EventSource,
			&success,
			&ev.LatencyMs,
			&ev.ErrorMessage,
			&ev.Payload,
			&eventAt,
		); err != nil {
			return nil, fmt.Errorf("scan node event: %w", err)
		}
		ev.Success = success == 1
		ev.EventAt, _ = parseTime(eventAt)
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node events: %w", err)
	}
	return out, nil
}

// ResolveIPPortKey finds ip:port key from table2.
func (s *Store) ResolveIPPortKey(ctx context.Context, nodeURI string, fallbackPort uint16) (string, error) {
	if s == nil || s.db == nil {
		return "", errors.New("sqlite store is not initialized")
	}
	nodeURI = strings.TrimSpace(nodeURI)
	if nodeURI == "" {
		return "", nil
	}

	var ipPortKey, ip string
	var listenPort int
	err := s.db.QueryRowContext(ctx, `
		SELECT ip_port_key, ip, listen_port
		FROM current_nodes
		WHERE node_uri = ?
		LIMIT 1`, nodeURI).Scan(&ipPortKey, &ip, &listenPort)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return BuildIPPortKey("", fallbackPort), nil
		}
		return "", fmt.Errorf("resolve ip_port_key: %w", err)
	}
	if strings.TrimSpace(ipPortKey) != "" {
		return strings.TrimSpace(ipPortKey), nil
	}
	port := intToPort(listenPort)
	if port == 0 {
		port = fallbackPort
	}
	return BuildIPPortKey(ip, port), nil
}

// PurgeOldEvents keeps only recent table3 rows.
func (s *Store) PurgeOldEvents(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite store is not initialized")
	}
	cutoff := time.Now().UTC().Add(-s.retention).Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `DELETE FROM node_events WHERE event_at < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("purge old node events: %w", err)
	}
	return nil
}

func (s *Store) maybePurgeOldEvents(ctx context.Context) {
	s.cleanupMu.Lock()
	if !s.lastCleanup.IsZero() && time.Since(s.lastCleanup) < time.Hour {
		s.cleanupMu.Unlock()
		return
	}
	s.lastCleanup = time.Now()
	s.cleanupMu.Unlock()
	_ = s.PurgeOldEvents(ctx)
}

func dedupeCurrentNodes(nodes []CurrentNode) []CurrentNode {
	if len(nodes) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(nodes))
	out := make([]CurrentNode, 0, len(nodes))
	for _, node := range nodes {
		node.URI = strings.TrimSpace(node.URI)
		if node.URI == "" {
			continue
		}
		if _, ok := seen[node.URI]; ok {
			continue
		}
		seen[node.URI] = struct{}{}
		node.Name = strings.TrimSpace(node.Name)
		if node.Name == "" {
			node.Name = node.URI
		}
		node.Protocol = parseProtocol(node.URI)
		now := time.Now().UTC()
		if node.FirstSeenAt.IsZero() {
			node.FirstSeenAt = now
		}
		if node.LastSeenAt.IsZero() {
			node.LastSeenAt = now
		}
		if node.LastUpdatedAt.IsZero() {
			node.LastUpdatedAt = now
		}
		if node.LastCheckAt.IsZero() {
			node.LastCheckAt = now
		}
		if node.LatencyMs == 0 {
			node.LatencyMs = -1
		}
		if node.HealthScore == 0 {
			node.HealthScore = -1
		}
		if node.Availability == 0 {
			node.Availability = availabilityUnknown
		}
		if strings.TrimSpace(node.Source) == "" {
			node.Source = "subscription"
		}
		node.IPPortKey = BuildIPPortKey(node.IP, node.ListenPort)
		out = append(out, node)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URI < out[j].URI })
	return out
}

func upsertCurrentNodeTx(ctx context.Context, tx *sql.Tx, node CurrentNode, active bool) error {
	node.Protocol = parseProtocol(node.URI)
	now := time.Now().UTC()
	if node.FirstSeenAt.IsZero() {
		node.FirstSeenAt = now
	}
	if node.LastSeenAt.IsZero() {
		node.LastSeenAt = now
	}
	if node.LastUpdatedAt.IsZero() {
		node.LastUpdatedAt = now
	}
	if node.LastCheckAt.IsZero() {
		node.LastCheckAt = now
	}
	if node.LatencyMs == 0 {
		node.LatencyMs = -1
	}
	if node.HealthScore == 0 {
		node.HealthScore = -1
	}
	if node.Availability == 0 {
		node.Availability = availabilityUnknown
	}
	if strings.TrimSpace(node.Source) == "" {
		node.Source = "subscription"
	}
	if strings.TrimSpace(node.Name) == "" {
		node.Name = node.URI
	}
	if strings.TrimSpace(node.IPPortKey) == "" {
		node.IPPortKey = BuildIPPortKey(node.IP, node.ListenPort)
	}

	_, err := tx.ExecContext(ctx, `
		INSERT INTO current_nodes (
			node_name, node_uri, node_source, protocol,
			listen_address, listen_port, username, password,
			first_seen_at, last_seen_at, last_updated_at, last_check_at,
			ip, latency_ms, health_score, availability,
			pure_score, fraud_score, bot_score, shared_users,
			ip_type, native_ip, country, city, location, isp, asn, info_source,
			ip_port_key, error_message, is_active
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(node_uri) DO UPDATE SET
			node_name=excluded.node_name,
			node_source=excluded.node_source,
			protocol=excluded.protocol,
			listen_address=CASE WHEN excluded.listen_address != '' THEN excluded.listen_address ELSE current_nodes.listen_address END,
			listen_port=CASE WHEN excluded.listen_port > 0 THEN excluded.listen_port ELSE current_nodes.listen_port END,
			username=CASE WHEN excluded.username != '' THEN excluded.username ELSE current_nodes.username END,
			password=CASE WHEN excluded.password != '' THEN excluded.password ELSE current_nodes.password END,
			last_seen_at=excluded.last_seen_at,
			last_updated_at=excluded.last_updated_at,
			last_check_at=CASE WHEN excluded.last_check_at != '' THEN excluded.last_check_at ELSE current_nodes.last_check_at END,
			ip=CASE WHEN excluded.ip != '' THEN excluded.ip ELSE current_nodes.ip END,
			latency_ms=CASE WHEN excluded.latency_ms >= 0 THEN excluded.latency_ms ELSE current_nodes.latency_ms END,
			health_score=CASE WHEN excluded.health_score >= 0 THEN excluded.health_score ELSE current_nodes.health_score END,
			availability=CASE WHEN excluded.availability >= 0 THEN excluded.availability ELSE current_nodes.availability END,
			pure_score=CASE WHEN excluded.pure_score != '' THEN excluded.pure_score ELSE current_nodes.pure_score END,
			fraud_score=CASE WHEN excluded.fraud_score != '' THEN excluded.fraud_score ELSE current_nodes.fraud_score END,
			bot_score=CASE WHEN excluded.bot_score != '' THEN excluded.bot_score ELSE current_nodes.bot_score END,
			shared_users=CASE WHEN excluded.shared_users != '' THEN excluded.shared_users ELSE current_nodes.shared_users END,
			ip_type=CASE WHEN excluded.ip_type != '' THEN excluded.ip_type ELSE current_nodes.ip_type END,
			native_ip=CASE WHEN excluded.native_ip != '' THEN excluded.native_ip ELSE current_nodes.native_ip END,
			country=CASE WHEN excluded.country != '' THEN excluded.country ELSE current_nodes.country END,
			city=CASE WHEN excluded.city != '' THEN excluded.city ELSE current_nodes.city END,
			location=CASE WHEN excluded.location != '' THEN excluded.location ELSE current_nodes.location END,
			isp=CASE WHEN excluded.isp != '' THEN excluded.isp ELSE current_nodes.isp END,
			asn=CASE WHEN excluded.asn > 0 THEN excluded.asn ELSE current_nodes.asn END,
			info_source=CASE WHEN excluded.info_source != '' THEN excluded.info_source ELSE current_nodes.info_source END,
			ip_port_key=CASE WHEN excluded.ip_port_key != '' THEN excluded.ip_port_key ELSE current_nodes.ip_port_key END,
			error_message=CASE WHEN excluded.error_message != '' THEN excluded.error_message ELSE current_nodes.error_message END,
			is_active=excluded.is_active;
	`,
		node.Name,
		node.URI,
		node.Source,
		node.Protocol,
		strings.TrimSpace(node.ListenAddr),
		int(node.ListenPort),
		strings.TrimSpace(node.Username),
		strings.TrimSpace(node.Password),
		node.FirstSeenAt.UTC().Format(time.RFC3339),
		node.LastSeenAt.UTC().Format(time.RFC3339),
		node.LastUpdatedAt.UTC().Format(time.RFC3339),
		node.LastCheckAt.UTC().Format(time.RFC3339),
		strings.TrimSpace(node.IP),
		node.LatencyMs,
		node.HealthScore,
		node.Availability,
		strings.TrimSpace(node.PureScore),
		strings.TrimSpace(node.FraudScore),
		strings.TrimSpace(node.BotScore),
		strings.TrimSpace(node.SharedUsers),
		strings.TrimSpace(node.IPType),
		strings.TrimSpace(node.NativeIP),
		strings.TrimSpace(node.Country),
		strings.TrimSpace(node.City),
		strings.TrimSpace(node.Location),
		strings.TrimSpace(node.ISP),
		node.ASN,
		strings.TrimSpace(node.InfoSource),
		strings.TrimSpace(node.IPPortKey),
		strings.TrimSpace(node.ErrorMessage),
		boolToInt(active),
	)
	if err != nil {
		return fmt.Errorf("upsert current node %s: %w", node.URI, err)
	}
	return nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func intToPort(v int) uint16 {
	if v <= 0 || v > 65535 {
		return 0
	}
	return uint16(v)
}

func parseProtocol(uri string) string {
	uri = strings.TrimSpace(uri)
	idx := strings.Index(uri, "://")
	if idx <= 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(uri[:idx]))
}

func timeToText(v *time.Time) string {
	if v == nil || v.IsZero() {
		return ""
	}
	return v.UTC().Format(time.RFC3339)
}

func parseTime(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func nowUTC(v time.Time) time.Time {
	if v.IsZero() {
		return time.Now().UTC()
	}
	return v.UTC()
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	vals := make([]string, n)
	for i := 0; i < n; i++ {
		vals[i] = "?"
	}
	return strings.Join(vals, ",")
}

func subscriptionNameFromURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw)
	}
	if host := strings.TrimSpace(u.Hostname()); host != "" {
		return host
	}
	return strings.TrimSpace(raw)
}

func calcHealthScore(success bool, latencyMs int64) float64 {
	if !success {
		return 0
	}
	if latencyMs <= 0 {
		return 90
	}
	score := 100 - float64(latencyMs)/12.0
	if score < 1 {
		score = 1
	}
	if score > 100 {
		score = 100
	}
	return score
}

// BuildIPPortKey builds key with ip:port from table2.
func BuildIPPortKey(ip string, port uint16) string {
	ip = strings.TrimSpace(ip)
	if ip != "" && port > 0 {
		return fmt.Sprintf("%s:%d", ip, port)
	}
	if ip != "" {
		return ip
	}
	if port > 0 {
		return fmt.Sprintf("unknown:%d", port)
	}
	return ""
}
