package cli

import "testing"

func TestUpgradeArchiveCandidatesPreferNewNaming(t *testing.T) {
	candidates, err := upgradeArchiveCandidates("0.2.1", "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(candidates))
	}
	if candidates[0].name != "agora-cli_v0.2.1_linux_amd64.tar.gz" {
		t.Fatalf("unexpected primary archive name: %q", candidates[0].name)
	}
	if candidates[1].name != "agora-cli-go_v0.2.1_linux_amd64.tar.gz" {
		t.Fatalf("unexpected legacy archive name: %q", candidates[1].name)
	}
}
