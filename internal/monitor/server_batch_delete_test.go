package monitor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"easy_proxies/internal/config"
)

type batchDeleteTestNodeManager struct {
	deleteErrs map[string]error
	deleted    []string
}

func (m *batchDeleteTestNodeManager) ListConfigNodes(context.Context) ([]config.NodeConfig, error) {
	return nil, nil
}

func (m *batchDeleteTestNodeManager) CreateNode(context.Context, config.NodeConfig) (config.NodeConfig, error) {
	return config.NodeConfig{}, nil
}

func (m *batchDeleteTestNodeManager) UpdateNode(context.Context, string, config.NodeConfig) (config.NodeConfig, error) {
	return config.NodeConfig{}, nil
}

func (m *batchDeleteTestNodeManager) DeleteNode(_ context.Context, name string) error {
	if err := m.deleteErrs[name]; err != nil {
		return err
	}
	m.deleted = append(m.deleted, name)
	return nil
}

func (m *batchDeleteTestNodeManager) TriggerReload(context.Context) error {
	return nil
}

func TestHandleConfigNodeBatchDelete(t *testing.T) {
	t.Parallel()

	nodeMgr := &batchDeleteTestNodeManager{
		deleteErrs: map[string]error{
			"missing": ErrNodeNotFound,
		},
	}
	server := &Server{nodeMgr: nodeMgr}

	req := httptest.NewRequest(http.MethodPost, "/api/nodes/config/batch-delete", strings.NewReader(`{"names":[" node-a ","missing","node-b","node-a",""]}`))
	rec := httptest.NewRecorder()

	server.handleConfigNodeBatchDelete(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp struct {
		Message string   `json:"message"`
		Success int      `json:"success"`
		Total   int      `json:"total"`
		Errors  []string `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if resp.Success != 2 {
		t.Fatalf("expected 2 successful deletions, got %d", resp.Success)
	}
	if resp.Total != 3 {
		t.Fatalf("expected total 3 unique names, got %d", resp.Total)
	}
	if len(resp.Errors) != 1 || !strings.Contains(resp.Errors[0], "missing") {
		t.Fatalf("expected one missing-node error, got %#v", resp.Errors)
	}
	if got := strings.Join(nodeMgr.deleted, ","); got != "node-a,node-b" {
		t.Fatalf("unexpected deleted nodes: %s", got)
	}
}

func TestHandleConfigNodeBatchDeleteBadRequest(t *testing.T) {
	t.Parallel()

	server := &Server{nodeMgr: &batchDeleteTestNodeManager{}}

	req := httptest.NewRequest(http.MethodPost, "/api/nodes/config/batch-delete", strings.NewReader(`{"names":[" ",""]}`))
	rec := httptest.NewRecorder()

	server.handleConfigNodeBatchDelete(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "至少提供一个有效节点名称") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestHandleConfigNodeBatchDeleteWithoutNodeManager(t *testing.T) {
	t.Parallel()

	server := &Server{}

	req := httptest.NewRequest(http.MethodPost, "/api/nodes/config/batch-delete", strings.NewReader(`{"names":["node-a"]}`))
	rec := httptest.NewRecorder()

	server.handleConfigNodeBatchDelete(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", rec.Code)
	}
}
