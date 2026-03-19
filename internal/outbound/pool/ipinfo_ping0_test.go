package pool

import "testing"

func TestParsePing0Shared_FromLegacyUsecount(t *testing.T) {
	html := `<div class="usecountbar">12</div>`
	if got := parsePing0Shared(html); got != "12" {
		t.Fatalf("unexpected shared users: %q", got)
	}
}

func TestParsePing0Shared_FromDetailNodes(t *testing.T) {
	html := `
<script>
	window.nodes = []
	window.nodes.push(n)
	window.nodes.push(n)
	window.nodes.push(n)
</script>`
	if got := parsePing0Shared(html); got != "3" {
		t.Fatalf("unexpected shared users: %q", got)
	}
}

func TestParsePing0Shared_FromDetailNodesZero(t *testing.T) {
	html := `<script>window.nodes = []</script>`
	if got := parsePing0Shared(html); got != "0" {
		t.Fatalf("unexpected shared users: %q", got)
	}
}
