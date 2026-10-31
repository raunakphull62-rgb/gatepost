package main

import (
	"testing"

	"gatepost/internal/snapshot"
)

// TestFeaturesEnvAllowList — GP_EDGE_FEATURES can NARROW the compiled-in
// feature set (or empty it via "none"), but it can NEVER claim a feature the
// binary does not implement: an unknown name is rejected at boot, never
// silently accepted as a gate that admits every snapshot.
func TestFeaturesEnvAllowList(t *testing.T) {
	// Default / unset = this build's full knowledge.
	t.Setenv("GP_EDGE_FEATURES", "")
	got, err := featuresEnv()
	if err != nil {
		t.Fatalf("default: %v", err)
	}
	if len(got) != len(snapshot.KnownFeatures) {
		t.Fatalf("default features = %v, want %v", got, snapshot.KnownFeatures)
	}

	// "none" = empty knowledge (old-style node).
	t.Setenv("GP_EDGE_FEATURES", "none")
	got, err = featuresEnv()
	if err != nil {
		t.Fatalf("none: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("none mode must yield an empty set, got %v", got)
	}

	// A known feature is accepted.
	t.Setenv("GP_EDGE_FEATURES", "waf")
	got, err = featuresEnv()
	if err != nil {
		t.Fatalf("known feature rejected: %v", err)
	}
	if len(got) != 1 || got[0] != snapshot.FeatureWAF {
		t.Fatalf("waf: got %v", got)
	}

	// Claiming a feature the binary does NOT implement is a boot-time error.
	t.Setenv("GP_EDGE_FEATURES", "waf,bananas,none")
	if _, err := featuresEnv(); err == nil {
		t.Fatal("an unknown feature must be rejected at boot, never accepted")
	}
}
