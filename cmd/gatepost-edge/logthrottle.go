// logThrottle: the rate limiter for repeated identical error lines (B3b
// item 6). A down API, a standing 401 or a loop of refused snapshots would
// otherwise write one log line per poll tick forever; each failure BRAND
// now emits at most one line per gap. State lives per brand, so different
// failures never suppress each other, and recovery lines never come through
// here at all — they are the changes an operator must always see.
package main

import (
	"sync"
	"time"
)

type logThrottle struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func newLogThrottle() *logThrottle {
	return &logThrottle{last: make(map[string]time.Time)}
}

// allow reports whether a line of the given brand may be logged NOW: the
// first call always true, repeats inside the gap false, and the first call
// after the gap true again.
func (t *logThrottle) allow(brand string, gap time.Duration, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if last, ok := t.last[brand]; ok && now.Sub(last) < gap {
		return false
	}
	t.last[brand] = now
	return true
}
