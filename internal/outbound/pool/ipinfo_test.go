package pool

import (
	"encoding/json"
	"testing"

	"easy_proxies/internal/monitor"
)

func TestBuildIPInfoFromIppurePayloadPrefersFraudNotPure(t *testing.T) {
	t.Parallel()

	info := buildIPInfoFromIppurePayload(ippureInfoResponse{
		IP:             "1.2.3.4",
		ASN:            json.Number("398704"),
		ASOrganization: "STACKS INC",
		Country:        "Singapore",
		City:           "Singapore",
		FraudScore:     json.Number("84"),
		IsBroadcast:    true,
	})

	if info.FraudScore != "84%" {
		t.Fatalf("expected fraud score 84%%, got %q", info.FraudScore)
	}
	if info.PureScore != "" {
		t.Fatalf("expected empty pure score, got %q", info.PureScore)
	}
	if info.FraudStatus != "ok" {
		t.Fatalf("expected fraud status ok, got %q", info.FraudStatus)
	}
	if info.BotStatus != "" {
		t.Fatalf("expected empty bot status before fallback, got %q", info.BotStatus)
	}
	if info.IPSrc != "广播" {
		t.Fatalf("expected IPSrc 广播, got %q", info.IPSrc)
	}
}

func TestApplyIPInfoStatusesMarksBlockedAndUnavailable(t *testing.T) {
	t.Parallel()

	info := &monitor.IPInfo{
		FraudScore: "84%",
	}

	applyIPInfoStatuses(info, errPing0Blocked, nil)

	if info.FraudStatus != "ok" {
		t.Fatalf("expected fraud status ok, got %q", info.FraudStatus)
	}
	if info.BotStatus != "unavailable" {
		t.Fatalf("expected bot status unavailable, got %q", info.BotStatus)
	}
	if info.SharedStatus != "blocked" {
		t.Fatalf("expected shared status blocked, got %q", info.SharedStatus)
	}
}
