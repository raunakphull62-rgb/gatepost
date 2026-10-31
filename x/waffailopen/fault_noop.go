//go:build !waffailopen_fault

package waffailopen

// FaultConfig is a no-op in production builds (no fault injection).
// The JSON field "fault" is still parsed for config compatibility, but
// injectFaults always returns false so the hooks are never triggered.
type FaultConfig struct{}

func (h *FailOpenHandler) injectFaults() bool { return false }
