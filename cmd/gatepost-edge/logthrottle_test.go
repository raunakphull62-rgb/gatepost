// Tests for the repeated-identical-error-line rate limiter (B3b item 6).
package main

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestLogThrottleBrands(t *testing.T) {
	th := newLogThrottle()
	gap := 30 * time.Second
	at := func(offset time.Duration) time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(offset) }

	if !th.allow("poll", gap, at(0)) {
		t.Fatal("the first line of a brand must always be allowed")
	}
	if th.allow("poll", gap, at(29*time.Second)) {
		t.Fatal("a repeat inside the gap was allowed — the flood is back")
	}
	if !th.allow("401", gap, at(29*time.Second)) {
		t.Fatal("one brand must not silence another")
	}
	if !th.allow("poll", gap, at(30*time.Second)) {
		t.Fatal("the first line after every gap must be allowed")
	}
}

// TestRepeatedFailureLinesThrottled pins the poller behavior: a down API
// keeps the loop retrying every interval, but "poll failed" is one line per
// gap and the backoff cap is announced exactly once for the whole outage.
// Twenty-five 1s ticks inside one 30s gap = two lines, not twenty-five.
func TestRepeatedFailureLinesThrottled(t *testing.T) {
	var numTicks int64
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return base.Add(time.Duration(numTicks) * time.Second) } // 1s per tick

	hook := &logHook{}
	cfg := Config{
		APIBase:     "http://127.0.0.1:1", // port 1: connection refused, forever
		Token:       "tok",
		Key:         makeKey(t),
		StateDir:    t.TempDir(),
		Interval:    time.Millisecond,
		BackoffCap:  8 * time.Millisecond, // cap reached at streak 3
		Client:      &http.Client{Timeout: time.Second},
		ErrorLogGap: 30 * time.Second,
		Now:         now,
		Rand01:      func() float64 { return 0 }, // no jitter in the cadence
		Log:         hook.log,
	}
	p := NewPoller(cfg)
	for i := 0; i < 25; i++ { // 25 ticks × 1s = 25s < one 30s gap
		numTicks = int64(i)
		p.tick(context.Background())
	}
	// The ladder walked (25 refused polls grew the streak), but the cap
	// announcement fired ONLY once:
	if n := hook.count("poll failure streak"); n != 1 {
		t.Fatalf("backoff-cap announcements = %d, want exactly 1 (log):\n%s", n, hook.all())
	}
	// Twenty-five connect-refused polls → ONE failure line: the first tick
	// logged; the next allowed line needs a 30s gap this clock never reaches.
	if n := hook.count("poll failed"); n != 1 {
		t.Fatalf("poll-failed lines = %d, want exactly 1 (log):\n%s", n, hook.all())
	}
}

// TestUnauthorized401OnePerGap: a standing 401 is loud, not a flood —
// the first instance per gap, suppressing the per-tick repeats in between.
func TestUnauthorized401OnePerGap(t *testing.T) {
	key := makeKey(t)
	api := newFakeAPI(t, key, "right-token")
	srv := api.serve()
	_ = srv // the fake answers 401 for a wrong token

	var numTicks int64
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	hook := &logHook{}
	cfg := newTestCfg(t, hook, t.TempDir(), srv.URL, "wrong-token", key)
	cfg.ErrorLogGap = 30 * time.Second
	cfg.Now = func() time.Time { return now.Add(time.Duration(numTicks) * time.Second) }

	p := NewPoller(cfg)
	for i := 0; i < 20; i++ {
		numTicks = int64(i)
		p.tick(context.Background())
	}
	if n := hook.count("401 from API"); n != 1 {
		t.Fatalf("401 lines = %d, want exactly 1 for 20 retries within the gap (log):\n%s", n, hook.all())
	}
}
