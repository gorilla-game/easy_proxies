package pool

import (
	"net/http"
	"testing"
)

func TestParseIplarkInfo_WithHeaders(t *testing.T) {
	headers := http.Header{
		"Client-Ip": []string{"1.1.1.1"},
		"Country":   []string{"US"},
		"City":      []string{"Los Angeles"},
		"Asn":       []string{"13335"},
	}
	body := "1.1.1.1\nUnited States AS13335 CLOUDFLARENET\n"

	info, ok := parseIplarkInfo(headers, body)
	if !ok {
		t.Fatalf("expected parse success")
	}
	if info.Source != "iplark" {
		t.Fatalf("unexpected source: %q", info.Source)
	}
	if info.IP != "1.1.1.1" {
		t.Fatalf("unexpected ip: %q", info.IP)
	}
	if info.Country != "US" {
		t.Fatalf("unexpected country: %q", info.Country)
	}
	if info.City != "Los Angeles" {
		t.Fatalf("unexpected city: %q", info.City)
	}
	if info.Location != "US Los Angeles" {
		t.Fatalf("unexpected location: %q", info.Location)
	}
	if info.ASN != 13335 {
		t.Fatalf("unexpected asn: %d", info.ASN)
	}
	if info.ISP != "CLOUDFLARENET" {
		t.Fatalf("unexpected isp: %q", info.ISP)
	}
}

func TestParseIplarkInfo_FromBodyFallback(t *testing.T) {
	headers := http.Header{}
	body := "38.181.86.100\n新加坡 AS398704 STACKS INC\n"

	info, ok := parseIplarkInfo(headers, body)
	if !ok {
		t.Fatalf("expected parse success")
	}
	if info.IP != "38.181.86.100" {
		t.Fatalf("unexpected ip: %q", info.IP)
	}
	if info.ASN != 398704 {
		t.Fatalf("unexpected asn: %d", info.ASN)
	}
	if info.Location != "新加坡" {
		t.Fatalf("unexpected location: %q", info.Location)
	}
	if info.ISP != "STACKS INC" {
		t.Fatalf("unexpected isp: %q", info.ISP)
	}
}

func TestParseIplarkInfo_FromHeadersOnly(t *testing.T) {
	headers := http.Header{
		"Client-Ip": []string{"38.181.86.100"},
		"Country":   []string{"SG"},
		"City":      []string{"Singapore"},
		"Asn":       []string{"398704"},
	}
	body := "<html><body><h1>403 Forbidden</h1></body></html>"

	info, ok := parseIplarkInfo(headers, body)
	if !ok {
		t.Fatalf("expected parse success from headers")
	}
	if info.IP != "38.181.86.100" {
		t.Fatalf("unexpected ip: %q", info.IP)
	}
	if info.ASN != 398704 {
		t.Fatalf("unexpected asn: %d", info.ASN)
	}
	if info.Location != "SG Singapore" {
		t.Fatalf("unexpected location: %q", info.Location)
	}
}
