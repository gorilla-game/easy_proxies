package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAllowsEmptyNodesForManagementOnlyStartup(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	nodesPath := filepath.Join(dir, "nodes.txt")

	if err := os.WriteFile(nodesPath, nil, 0o644); err != nil {
		t.Fatalf("write nodes file: %v", err)
	}

	configYAML := []byte(`mode: pool
management:
  enabled: true
  listen: 127.0.0.1:9090
listener:
  address: 127.0.0.1
  port: 2323
nodes_file: nodes.txt
`)
	if err := os.WriteFile(configPath, configYAML, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected config, got nil")
	}
	if len(cfg.Nodes) != 0 {
		t.Fatalf("expected no loaded nodes, got %d", len(cfg.Nodes))
	}
	if cfg.NodesFile != nodesPath {
		t.Fatalf("expected resolved nodes_file %q, got %q", nodesPath, cfg.NodesFile)
	}
}
