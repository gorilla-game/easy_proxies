package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"easy_proxies/internal/boxmgr"
	"easy_proxies/internal/config"
	"easy_proxies/internal/monitor"
	"easy_proxies/internal/storage"
	"easy_proxies/internal/subscription"
)

// Run builds the runtime components from config and blocks until shutdown.
func Run(ctx context.Context, cfg *config.Config) error {
	var nodeStore *storage.Store
	if cfg.UseSQLite() {
		s, err := storage.Open(cfg.Storage.SQLitePath)
		if err != nil {
			return fmt.Errorf("open sqlite store: %w", err)
		}
		nodeStore = s
		defer nodeStore.Close()

		if err := syncSubscriptionsToStore(ctx, nodeStore, cfg); err != nil {
			return fmt.Errorf("sync subscriptions to sqlite: %w", err)
		}

		dbNodes, err := nodeStore.LoadActiveNodes(ctx)
		if err != nil {
			return fmt.Errorf("load nodes from sqlite: %w", err)
		}
		if len(dbNodes) == 0 && len(cfg.Nodes) > 0 {
			if err := nodeStore.ReplaceAllCurrentNodes(ctx, buildStoreNodes(cfg.Nodes)); err != nil {
				return fmt.Errorf("bootstrap sqlite nodes: %w", err)
			}
			dbNodes, err = nodeStore.LoadActiveNodes(ctx)
			if err != nil {
				return fmt.Errorf("reload sqlite nodes after bootstrap: %w", err)
			}
		}
		if len(dbNodes) > 0 {
			cfg.Nodes = buildConfigNodes(dbNodes)
		}
	}

	// Build monitor config
	proxyUsername := cfg.Listener.Username
	proxyPassword := cfg.Listener.Password
	if cfg.Mode == "multi-port" || cfg.Mode == "hybrid" {
		proxyUsername = cfg.MultiPort.Username
		proxyPassword = cfg.MultiPort.Password
	}

	checkDir := "checker"
	if cfg != nil {
		if cfgPath := cfg.FilePath(); cfgPath != "" {
			checkDir = filepath.Join(filepath.Dir(cfgPath), "checker")
		}
	}

	monitorCfg := monitor.Config{
		Enabled:        cfg.ManagementEnabled(),
		Listen:         cfg.Management.Listen,
		ProbeTarget:    cfg.Management.ProbeTarget,
		Password:       cfg.Management.Password,
		APIToken:       cfg.Management.APIToken,
		CORSOrigins:    cfg.Management.CORSOrigins,
		ProxyUsername:  proxyUsername,
		ProxyPassword:  proxyPassword,
		ExternalIP:     cfg.ExternalIP,
		CheckResultDir: checkDir,
		Store:          nodeStore,
	}

	// Create and start BoxManager
	boxMgr := boxmgr.New(cfg, monitorCfg, boxmgr.WithNodeStore(nodeStore))
	if err := boxMgr.Start(ctx); err != nil {
		return fmt.Errorf("start box manager: %w", err)
	}
	defer boxMgr.Close()

	// Wire up config to monitor server for settings API
	if server := boxMgr.MonitorServer(); server != nil {
		server.SetConfig(cfg)
	}

	// Create and start SubscriptionManager.
	// The manager handles both periodic refresh (when enabled) and one-shot background bootstrap.
	var subMgr *subscription.Manager
	subMgr = subscription.New(cfg, boxMgr, subscription.WithStore(nodeStore))
	subMgr.Start()
	defer subMgr.Stop()

	// Wire up subscription manager to monitor server for API endpoints
	if server := boxMgr.MonitorServer(); server != nil {
		server.SetSubscriptionRefresher(subMgr)
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case <-ctx.Done():
		fmt.Println("Context cancelled, initiating graceful shutdown...")
	case sig := <-sigCh:
		fmt.Printf("Received %s, initiating graceful shutdown...\n", sig)
	}

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Graceful shutdown sequence
	fmt.Println("Stopping subscription manager...")
	if subMgr != nil {
		subMgr.Stop()
	}

	fmt.Println("Stopping box manager...")
	if err := boxMgr.Close(); err != nil {
		fmt.Printf("Error closing box manager: %v\n", err)
	}

	// Wait for connections to drain
	fmt.Println("Waiting for connections to drain...")
	select {
	case <-time.After(2 * time.Second):
		fmt.Println("Graceful shutdown completed")
	case <-shutdownCtx.Done():
		fmt.Println("Shutdown timeout exceeded, forcing exit")
	}

	return nil
}

func syncSubscriptionsToStore(ctx context.Context, store *storage.Store, cfg *config.Config) error {
	if store == nil || cfg == nil {
		return nil
	}
	records := make([]storage.SubscriptionRecord, 0, len(cfg.Subscriptions))
	interval := int64(cfg.SubscriptionRefresh.Interval / time.Second)
	if interval < 0 {
		interval = 0
	}
	for idx, subURL := range cfg.Subscriptions {
		subURL = strings.TrimSpace(subURL)
		if subURL == "" {
			continue
		}
		records = append(records, storage.SubscriptionRecord{
			Name:             fmt.Sprintf("subscription-%d", idx+1),
			SubscriptionURL:  subURL,
			EnabledUpdate:    true,
			IntervalSeconds:  interval,
			Collector:        "http",
			Parser:           "auto",
			Normalized:       true,
			UnifiedStructure: true,
			Deduped:          true,
		})
	}
	return store.UpsertSubscriptions(ctx, records)
}

func buildStoreNodes(nodes []config.NodeConfig) []storage.CurrentNode {
	now := time.Now().UTC()
	out := make([]storage.CurrentNode, 0, len(nodes))
	for _, node := range nodes {
		uri := strings.TrimSpace(node.URI)
		if uri == "" {
			continue
		}
		source := strings.ToLower(strings.TrimSpace(string(node.Source)))
		if source == "" {
			source = string(config.NodeSourceSubscription)
		}
		out = append(out, storage.CurrentNode{
			Name:          strings.TrimSpace(node.Name),
			URI:           uri,
			Source:        source,
			ListenPort:    node.Port,
			Username:      strings.TrimSpace(node.Username),
			Password:      strings.TrimSpace(node.Password),
			LatencyMs:     -1,
			HealthScore:   -1,
			Availability:  -1,
			Active:        true,
			FirstSeenAt:   now,
			LastSeenAt:    now,
			LastUpdatedAt: now,
			LastCheckAt:   now,
		})
	}
	return out
}

func buildConfigNodes(rows []storage.CurrentNode) []config.NodeConfig {
	out := make([]config.NodeConfig, 0, len(rows))
	for _, row := range rows {
		if strings.TrimSpace(row.URI) == "" {
			continue
		}
		source := config.NodeSourceSubscription
		switch strings.ToLower(strings.TrimSpace(row.Source)) {
		case string(config.NodeSourceInline):
			source = config.NodeSourceInline
		case string(config.NodeSourceFile):
			source = config.NodeSourceFile
		case string(config.NodeSourceSubscription):
			source = config.NodeSourceSubscription
		}
		out = append(out, config.NodeConfig{
			Name:     strings.TrimSpace(row.Name),
			URI:      strings.TrimSpace(row.URI),
			Port:     row.ListenPort,
			Username: strings.TrimSpace(row.Username),
			Password: strings.TrimSpace(row.Password),
			Source:   source,
		})
	}
	return out
}
