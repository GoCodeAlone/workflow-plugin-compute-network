package main

import "testing"

func TestRunConformanceHelpReturnsSuccess(t *testing.T) {
	if err := runConformance([]string{"--help"}); err != nil {
		t.Fatalf("help should not be treated as an error: %v", err)
	}
}
