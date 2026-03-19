package pool

import (
	"encoding/json"
	"testing"
)

func TestParseDKLYInfo_CleanISP(t *testing.T) {
	payload := dklyInfoResponse{
		IP: "38.181.86.100",
		Security: dklySecurityResponse{
			IsAbuser:        false,
			IsAttacker:      false,
			IsBogon:         false,
			IsCloudProvider: false,
			IsProxy:         false,
			IsRelay:         false,
			IsTor:           false,
			IsTorExit:       false,
			IsVPN:           false,
			IsAnonymous:     false,
			IsThreat:        false,
		},
	}
	payload.Connection.ASN = json.Number("398704")
	payload.Connection.Organization = "STACKS INC"
	payload.Connection.Type = "isp"
	payload.Company.Name = "Cogent Communications"
	payload.Company.Type = "isp"
	payload.Location.Country.Code = "SG"
	payload.Location.Country.Name = "Singapore"
	payload.Location.Region.Name = "Central Singapore"
	payload.Location.City = "Singapore"

	info, ok := parseDKLYInfo(payload)
	if !ok {
		t.Fatalf("expected parse success")
	}
	if info.Source != "dkly" {
		t.Fatalf("unexpected source: %q", info.Source)
	}
	if info.IP != "38.181.86.100" {
		t.Fatalf("unexpected ip: %q", info.IP)
	}
	if info.Country != "Singapore" {
		t.Fatalf("unexpected country: %q", info.Country)
	}
	if info.City != "Singapore" {
		t.Fatalf("unexpected city: %q", info.City)
	}
	if info.Location != "Singapore Central Singapore Singapore" {
		t.Fatalf("unexpected location: %q", info.Location)
	}
	if info.ASN != 398704 {
		t.Fatalf("unexpected asn: %d", info.ASN)
	}
	if info.ISP != "STACKS INC" {
		t.Fatalf("unexpected isp: %q", info.ISP)
	}
	if info.IPAttr != "住宅" {
		t.Fatalf("unexpected ip_attr: %q", info.IPAttr)
	}
	if info.IPSrc != "原生" {
		t.Fatalf("unexpected ip_src: %q", info.IPSrc)
	}
	if info.PureScore != "100%" {
		t.Fatalf("unexpected pure score: %q", info.PureScore)
	}
	if info.FraudScore != "100%" {
		t.Fatalf("unexpected fraud score: %q", info.FraudScore)
	}
}

func TestParseDKLYInfo_RiskyAnonymous(t *testing.T) {
	payload := dklyInfoResponse{
		IP: "8.8.8.8",
		Security: dklySecurityResponse{
			IsCloudProvider: true,
			IsProxy:         true,
			IsVPN:           true,
			IsThreat:        true,
		},
	}
	payload.Connection.ASN = json.Number("15169")
	payload.Connection.Organization = "Google LLC"
	payload.Connection.Type = "hosting"
	payload.Company.Type = "hosting"
	payload.Location.Country.Name = "United States"
	payload.Location.City = "Mountain View"

	info, ok := parseDKLYInfo(payload)
	if !ok {
		t.Fatalf("expected parse success")
	}
	if info.IPAttr != "机房" {
		t.Fatalf("unexpected ip_attr: %q", info.IPAttr)
	}
	if info.IPSrc != "广播" {
		t.Fatalf("unexpected ip_src: %q", info.IPSrc)
	}
	if info.PureScore != "60%" {
		t.Fatalf("unexpected pure score: %q", info.PureScore)
	}
	if info.FraudScore != "60%" {
		t.Fatalf("unexpected fraud score: %q", info.FraudScore)
	}
}
