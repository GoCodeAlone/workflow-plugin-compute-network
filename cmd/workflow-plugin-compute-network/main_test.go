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
		"--external-peer-multi-node",
	})
	if err == nil || !strings.Contains(err.Error(), "external peer flags are only valid with --mode p2p") {
		t.Fatalf("expected external peer mode error, got %v", err)
	}
}

func TestRunConformanceRejectsCaptiveTopologyFlagsOutsideCaptive(t *testing.T) {
	err := runConformance([]string{
		"--mode", "p2p",
		"--artifact", t.TempDir() + "/p2p.json",
		"--captive-topology-ref", "workflow-run:example/task:captive",
	})
	if err == nil || !strings.Contains(err.Error(), "captive topology flags are only valid with --mode captive") {
		t.Fatalf("expected captive topology mode error, got %v", err)
	}
}

func TestRunConformanceRejectsCaptiveMultiNodeWithoutTopologyRef(t *testing.T) {
	err := runConformance([]string{
		"--mode", "captive",
		"--artifact", t.TempDir() + "/captive.json",
		"--captive-external-multi-node",
	})
	if err == nil || !strings.Contains(err.Error(), "captive topology_ref is required") {
		t.Fatalf("expected captive topology ref error, got %v", err)
	}
}
