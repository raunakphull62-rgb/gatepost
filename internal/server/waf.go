// B3c item 2: per-domain WAF mode and rule exclusions.
// One shared Coraza instance for the whole edge; per-host behaviour comes
// from phase:1 rules scoped to the Host header that use ctl actions:
//   SecRule REQUEST_HEADERS:Host "@streq <host>" "id:<n>,phase:1,pass,nolog,ctl:ruleEngine=Off"
//   SecRule REQUEST_HEADERS:Host "@streq <host>" "id:<n>,phase:1,pass,nolog,ctl:ruleRemoveById=<id>"
// coraza v3.8.1 supports both ctl actions at phase:1, BEFORE any CRS rule fires.
package server

import (
	"net/http"
	"strconv"
	"strings"

	"gatepost/internal/snapshot"
)

var validWAFModes = map[string]bool{
	"off":       true,
	"detection": true,
	"blocking":  true,
}

// wafBody is the strict input for PUT /v1/domains/{id}/waf.
type wafBody struct {
	Mode            string `json:"mode"`
	ExcludedRuleIDs []int  `json:"excluded_rule_ids"`
}

// checkWAF validates mode and rule IDs. Returns "" on ok.
func checkWAF(b wafBody) string {
	if b.Mode != "" && !validWAFModes[b.Mode] {
		return "mode must be off, detection, or blocking"
	}
	for _, id := range b.ExcludedRuleIDs {
		if id < 1 || id > 999999 {
			return "rule id " + strconv.Itoa(id) + " out of range (1..999999)"
		}
	}
	return ""
}

// putDomainWAF sets the WAF mode and excluded rule IDs for one domain.
// Tenant isolation via ownerDomain (404 if not the caller's).
func (s *Server) putDomainWAF(w http.ResponseWriter, r *http.Request, p *Principal) {
	d, ok := s.ownerDomain(w, r, p)
	if !ok {
		return
	}
	var b wafBody
	if !readJSON(w, r, &b) {
		return
	}
	if msg := checkWAF(b); msg != "" {
		fail(w, http.StatusBadRequest, msg)
		return
	}
	mode := b.Mode
	if mode == "" {
		mode = "detection"
	}
	// nil slice → NULL → NOT NULL column violation; coerce to empty.
	if b.ExcludedRuleIDs == nil {
		b.ExcludedRuleIDs = []int{}
	}
	oldMode := d.WAFMode
	if oldMode == "" {
		oldMode = "detection"
	}
	oldExclusions := d.ExcludedRuleIDs
	if oldExclusions == nil {
		oldExclusions = []int{}
	}
	var _id string
	if err := s.pool.QueryRow(r.Context(), `UPDATE domains SET
		waf_mode = $1, excluded_rule_ids = $2
		WHERE id::text = $3 AND owner_user_id = $4
		RETURNING id::text`,
		mode, b.ExcludedRuleIDs, d.ID, p.UserID).Scan(&_id); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.recordWAFChange(r, d.ID, p.UserID, "mode", oldMode, mode)
	s.recordWAFCorrections(r, d.ID, p.UserID, oldExclusions, b.ExcludedRuleIDs)
	s.invalidateSnapshot()
	d, err := s.scanDomain(s.pool.QueryRow(r.Context(),
		`SELECT `+domainCols+` FROM domains WHERE id::text = $1 AND owner_user_id = $2`,
		d.ID, p.UserID))
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"domain": d})
}

func (s *Server) recordWAFChange(r *http.Request, domainID, userID, action, old, new string) {
	_, _ = s.pool.Exec(r.Context(), `INSERT INTO domain_waf_changes
		(domain_id, changed_by, action, old_value, new_value) VALUES ($1, $2, $3, $4, $5)`,
		domainID, userID, action, old, new)
}

func (s *Server) recordWAFCorrections(r *http.Request, domainID string, userID string, old, new []int) {
	oldSet := make(map[int]bool, len(old))
	for _, id := range old {
		oldSet[id] = true
	}
	newSet := make(map[int]bool, len(new))
	for _, id := range new {
		newSet[id] = true
	}
	for _, id := range old {
		if !newSet[id] {
			s.recordWAFChange(r, domainID, userID, "exclude_remove", strconv.Itoa(id), "")
		}
	}
	for _, id := range new {
		if !oldSet[id] {
			s.recordWAFChange(r, domainID, userID, "exclude_add", "", strconv.Itoa(id))
		}
	}
}

// validateHostForWAF checks that a hostname is safe to embed in a coraza
// SecRule match: strict LDH labels, no quotes, no newlines, no control chars.
// This runs at generation time on snapshot domains (already normalized at claim
// time), but the check is belt-and-suspenders: a hostile snapshot
// value never reaches the directives string.
func validateHostForWAF(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if strings.ContainsAny(host, "\"\r\n\x00\\") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// snapshotDomainWAF returns the WAF mode for a domain, defaulting to
// "detection" for old schema-1 snapshots that omit the field.
func snapshotDomainWAF(d snapshot.Domain) string {
	if d.WAFMode == "" {
		return "detection"
	}
	if !validWAFModes[d.WAFMode] {
		return "detection"
	}
	return d.WAFMode
}
