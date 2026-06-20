package main

import (
	"strings"
	"testing"
)

func TestRunConformanceHelpReturnsSuccess(t *testing.T) {
	if err := runConformance([]string{"--help"}); err != nil {
		t.Fatalf("help should not be treated as an error: %v", err)
	}
}

func TestRunConformanceRejectsExternalPeerFlagsOutsideP2P(t *testing.T) {
	err := runConformance([]string{
		"--mode", "captive",
		"--artifact", t.TempDir() + "/captive.json",
		"--external-peer-id", "peer-source-external",
	})
	if err == nil || !strings.Contains(err.Error(), "external peer flags are only valid with --mode p2p") {
		t.Fatalf("expected external peer mode error, got %v", err)
	}
}
