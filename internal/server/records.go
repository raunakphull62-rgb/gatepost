// B2 item 12: zone records. One zone per nameserver-mode domain; records
// are owner-scoped through ownerDomain, validated per type, CNAME-exclusive
// per name, capped per zone, and every mutation writes a history row
// (who/when/old/new) so a later rollback is possible. History of DELETED
// records stays in the table (later tooling reads it); GET on a deleted
// record id is the usual 404.
package server

import (
	"errors"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type recordRow struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	TTL       int       `json:"ttl"`
	Priority  *int      `json:"priority"`
	CreatedAt time.Time `json:"created_at"`
}

const recordCols = `id::text, name, type, value, ttl, priority, created_at`

type recordChange struct {
	Action    string    `json:"action"`
	OldValue  *string   `json:"old_value"`
	NewValue  *string   `json:"new_value"`
	ChangedBy string    `json:"changed_by"`
	ChangedAt time.Time `json:"changed_at"`
}

const changesCols = `action, old_value, new_value, changed_by::text, changed_at`

func (s *Server) scanRecord(row pgx.Row) (recordRow, error) {
	var rc recordRow
	err := row.Scan(&rc.ID, &rc.Name, &rc.Type, &rc.Value, &rc.TTL, &rc.Priority, &rc.CreatedAt)
	return rc, err
}

// zoneForDomain resolves the caller's zone; a cname domain has none (409
// for the owner, foreign ids were already a 404 via ownerDomain).
func (s *Server) zoneForDomain(w http.ResponseWriter, r *http.Request, d domainRow) (string, bool) {
	var id string
	err := s.pool.QueryRow(r.Context(),
		`SELECT id::text FROM zones WHERE domain_id = $1`, d.ID).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, http.StatusConflict, "records need a nameserver-mode domain")
			return "", false
		}
		fail(w, http.StatusInternalServerError, "internal error")
		return "", false
	}
	return id, true
}

// recordBody — name/type/value are required; ttl defaults 3600.
type recordBody struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	TTL      *int   `json:"ttl"`
	Priority *int   `json:"priority"`
}

// patchBody is the partial update of one record; value optional.
type patchBody struct {
	Value    *string `json:"value"`
	TTL      *int    `json:"ttl"`
	Priority *int    `json:"priority"`
}

var caaValue = regexp.MustCompile(`^([0-9]{1,3})\s+(issue|issuewild|iodef)\s+.+$`)
var srvValue = regexp.MustCompile(`^([0-9]+)\s+([0-9]+)\s+(\S+)$`)

// validateName — relative zone name: "@" or label chains of [a-z0-9_-]
// (underscores for _tcp/_dmarc-style service names), 63 per label, no
// leading/trailing hyphen.
func validateName(n string) error {
	if n == "@" {
		return nil
	}
	if len(n) > 100 {
		return errors.New("name too long")
	}
	for _, label := range strings.Split(n, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("bad label length")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
				return errors.New("bad character in name")
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("bad hyphen position")
		}
	}
	return nil
}

// validateRecordTarget — record VALUES that are hostnames: trailing dot ok,
// labels of [a-z0-9-] (no underscores), 253 total, never an IP literal.
func validateRecordTarget(v string) error {
	v = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")
	if v == "" {
		return errors.New("empty hostname")
	}
	if len(v) > 253 {
		return errors.New("hostname too long")
	}
	if net.ParseIP(v) != nil {
		return errors.New("an IP literal is not a hostname")
	}
	for _, label := range strings.Split(v, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("bad label in hostname")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return errors.New("bad character in hostname")
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("bad hyphen position")
		}
	}
	return nil
}

// checkRecord validates name/type/value/ttl/priority per type; "" on ok.
func checkRecord(b recordBody) string {
	if validateName(strings.ToLower(strings.TrimSpace(b.Name))) != nil {
		return "invalid record name"
	}
	b.Type = strings.ToUpper(b.Type)
	b.Value = strings.TrimSpace(b.Value)
	switch b.Type {
	case "A":
		ip := net.ParseIP(b.Value)
		if ip == nil || ip.To4() == nil {
			return "A value must be an IPv4 address"
		}
	case "AAAA":
		ip := net.ParseIP(b.Value)
		if ip == nil || ip.To4() != nil {
			return "AAAA value must be an IPv6 address"
		}
	case "CNAME", "NS":
		if validateRecordTarget(b.Value) != nil {
			return b.Type + " value must be a hostname"
		}
	case "MX":
		if b.Priority == nil {
			return "MX needs a priority"
		}
		if validateRecordTarget(b.Value) != nil {
			return "MX value must be a hostname"
		}
	case "TXT":
		if len(b.Value) > 255 || strings.ContainsAny(b.Value, "\r\n\x00") {
			return "TXT value must be 255 printable chars max"
		}
	case "SRV":
		if b.Priority == nil {
			return "SRV needs a priority"
		}
		m := srvValue.FindStringSubmatch(b.Value)
		if m == nil {
			return `SRV value must be "weight port target"`
		}
		if _, err1 := strconv.Atoi(m[1]); err1 != nil {
			return "bad SRV weight"
		}
		if _, err2 := strconv.Atoi(m[2]); err2 != nil {
			return "bad SRV port"
		}
		if m[3] != "." && validateRecordTarget(m[3]) != nil {
			return "SRV target must be a hostname or ."
		}
	case "CAA":
		if !caaValue.MatchString(b.Value) {
			return `CAA value must be "flag tag value"`
		}
		if flag, _ := strconv.Atoi(caaValue.FindStringSubmatch(b.Value)[1]); flag > 255 {
			return "CAA flag must be 0..255"
		}
	default:
		return "type must be one of A AAAA CNAME MX TXT NS SRV CAA"
	}
	if b.TTL != nil && (*b.TTL < 60 || *b.TTL > 86400) {
		return "ttl must be 60..86400"
	}
	if b.Priority != nil && (*b.Priority < 0 || *b.Priority > 65535) {
		return "priority must be 0..65535"
	}
	return ""
}

// addRecord POST /v1/domains/{id}/records — with history row, CNAME
// exclusivity, and the per-zone cap in one transaction.
func (s *Server) addRecord(w http.ResponseWriter, r *http.Request, p *Principal) {
	d, ok := s.ownerDomain(w, r, p)
	if !ok {
		return
	}
	zone, ok := s.zoneForDomain(w, r, d)
	if !ok {
		return
	}
	var b recordBody
	if !readJSON(w, r, &b) {
		return
	}
	if msg := checkRecord(b); msg != "" {
		fail(w, http.StatusUnprocessableEntity, msg)
		return
	}
	if b.TTL == nil {
		b.TTL = intPtr(3600)
	}
	b.Name = strings.ToLower(strings.TrimSpace(b.Name))
	b.Value = strings.TrimSpace(b.Value)

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback(r.Context())
	if b.Type == "CNAME" { // a CNAME name carries nothing else
		var taken bool
		if err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM records
			WHERE zone_id = $1 AND name = $2)`, zone, b.Name).Scan(&taken); err == nil && taken {
			fail(w, http.StatusConflict, "another record already exists at this name")
			return
		}
	} else { // nothing can live beside a CNAME
		var cnamed bool
		if err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM records
			WHERE zone_id = $1 AND name = $2 AND type = 'CNAME')`, zone, b.Name).Scan(&cnamed); err == nil && cnamed {
			fail(w, http.StatusConflict, "a CNAME already exists at this name")
			return
		}
	}
	var count int
	if err := tx.QueryRow(r.Context(),
		`SELECT count(*) FROM records WHERE zone_id = $1`, zone).Scan(&count); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if count >= s.cfg.MaxRecords {
		fail(w, http.StatusUnprocessableEntity, "zone record limit reached")
		return
	}
	rc, ierr := s.scanRecord(tx.QueryRow(r.Context(), `INSERT INTO records
		(zone_id, name, type, value, ttl, priority) VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING `+recordCols, zone, b.Name, b.Type, b.Value, *b.TTL, b.Priority))
	if ierr != nil {
		if isUniqueViolation(ierr) { // concurrent CNAMEs (partial unique index)
			fail(w, http.StatusConflict, "a CNAME already exists at this name")
			return
		}
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if _, err := tx.Exec(r.Context(), `INSERT INTO record_changes
		(record_id, zone_id, changed_by, action, new_value) VALUES ($1, $2, $3, 'create', $4)`,
		rc.ID, zone, p.UserID, b.Value); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"record": rc})
}

// listRecords GET /v1/domains/{id}/records
func (s *Server) listRecords(w http.ResponseWriter, r *http.Request, p *Principal) {
	d, ok := s.ownerDomain(w, r, p)
	if !ok {
		return
	}
	zone, ok := s.zoneForDomain(w, r, d)
	if !ok {
		return
	}
	rows, err := s.pool.Query(r.Context(), `SELECT `+recordCols+` FROM records
		WHERE zone_id = $1 ORDER BY name, type, id::text`, zone)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()
	list := []recordRow{}
	for rows.Next() {
		rc, err := s.scanRecord(rows)
		if err != nil {
			fail(w, http.StatusInternalServerError, "internal error")
			return
		}
		list = append(list, rc)
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": list})
}

// oneRecord fetches a live record of the caller's zone.
func (s *Server) oneRecord(w http.ResponseWriter, r *http.Request, d domainRow) (zone, id string, rc recordRow, ok bool) {
	zone, zok := s.zoneForDomain(w, r, d)
	if !zok {
		return "", "", recordRow{}, false
	}
	id = r.PathValue("rid")
	rc, err := s.scanRecord(s.pool.QueryRow(r.Context(), `SELECT `+recordCols+`
		FROM records WHERE zone_id = $1 AND id = $2`, zone, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, http.StatusNotFound, "not found")
			return "", "", recordRow{}, false
		}
		fail(w, http.StatusInternalServerError, "internal error")
		return "", "", recordRow{}, false
	}
	return zone, id, rc, true
}

// getRecord GET /v1/domains/{id}/records/{rid} — record + its history.
func (s *Server) getRecord(w http.ResponseWriter, r *http.Request, p *Principal) {
	d, ok := s.ownerDomain(w, r, p)
	if !ok {
		return
	}
	_, _, rc, ok := s.oneRecord(w, r, d)
	if !ok {
		return
	}
	hist, err := s.recordHistory(r, rc.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"record": rc, "history": hist})
}

func (s *Server) recordHistory(r *http.Request, recID string) ([]recordChange, error) {
	rows, err := s.pool.Query(r.Context(), `SELECT `+changesCols+`
		FROM record_changes WHERE record_id = $1 ORDER BY changed_at, id`, recID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hist := []recordChange{}
	for rows.Next() {
		var h recordChange
		if err := rows.Scan(&h.Action, &h.OldValue, &h.NewValue, &h.ChangedBy, &h.ChangedAt); err != nil {
			return nil, err
		}
		hist = append(hist, h)
	}
	return hist, rows.Err()
}

// patchRecord PATCH /v1/domains/{id}/records/{rid} — value/ttl/priority
// only (name/type are immutable); history row on every change.
func (s *Server) patchRecord(w http.ResponseWriter, r *http.Request, p *Principal) {
	d, ok := s.ownerDomain(w, r, p)
	if !ok {
		return
	}
	var b patchBody
	if !readJSON(w, r, &b) {
		return
	}
	if b.Value == nil && b.TTL == nil && b.Priority == nil {
		fail(w, http.StatusUnprocessableEntity, "nothing to change")
		return
	}
	zone, _, rc, ok := s.oneRecord(w, r, d)
	if !ok {
		return
	}
	// validate the new value against the record's own type; MX/SRV keep
	// their stored priority unless the body says otherwise
	pri := b.Priority
	if pri == nil {
		pri = rc.Priority
	}
	newVal := rc.Value
	if b.Value != nil {
		newVal = strings.TrimSpace(*b.Value)
	}
	if msg := typeValueCheck(rc.Type, newVal, pri); msg != "" {
		fail(w, http.StatusUnprocessableEntity, msg)
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback(r.Context())
	old := rc.Value
	newTTL := rc.TTL
	if b.TTL != nil {
		if *b.TTL < 60 || *b.TTL > 86400 {
			fail(w, http.StatusUnprocessableEntity, "ttl must be 60..86400")
			return
		}
		newTTL = *b.TTL
	}
	newPri := rc.Priority
	if b.Priority != nil {
		newPri = b.Priority
	}
	updated, uerr := s.scanRecord(tx.QueryRow(r.Context(), `UPDATE records SET
		value = $3, ttl = $4, priority = $5, created_at = created_at
		WHERE zone_id = $1 AND id = $2 RETURNING `+recordCols,
		zone, rc.ID, newVal, newTTL, newPri))
	if uerr != nil {
		if errors.Is(uerr, pgx.ErrNoRows) {
			fail(w, http.StatusNotFound, "not found")
			return
		}
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if _, err := tx.Exec(r.Context(), `INSERT INTO record_changes
		(record_id, zone_id, changed_by, action, old_value, new_value)
		VALUES ($1, $2, $3, 'update', $4, $5)`, rc.ID, zone, p.UserID, old, newVal); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"record": updated})
}

// deleteRecord DELETE /v1/domains/{id}/records/{rid}
func (s *Server) deleteRecord(w http.ResponseWriter, r *http.Request, p *Principal) {
	d, ok := s.ownerDomain(w, r, p)
	if !ok {
		return
	}
	zone, _, rc, ok := s.oneRecord(w, r, d)
	if !ok {
		return
	}
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err := tx.Exec(r.Context(), `INSERT INTO record_changes
		(record_id, zone_id, changed_by, action, old_value)
		VALUES ($1, $2, $3, 'delete', $4)`, rc.ID, zone, p.UserID, rc.Value); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if _, err := tx.Exec(r.Context(), `DELETE FROM records WHERE zone_id = $1 AND id = $2`,
		zone, rc.ID); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// typeValueCheck validates one value against one type (PATCH path).
func typeValueCheck(typ, val string, pri *int) string {
	b := recordBody{Name: "@", Type: typ, Value: val, Priority: pri}
	if b.TTL == nil {
		b.TTL = intPtr(60)
	}
	if msg := checkRecord(b); msg != "" {
		// the generic check covers the type/value rules we care about
		return msg
	}
	return ""
}

func intPtr(v int) *int { return &v }
