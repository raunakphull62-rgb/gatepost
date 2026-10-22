package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const schemaUserInsert = `INSERT INTO users (id, email, email_verified) VALUES (gen_random_uuid(), $1, true) RETURNING id::text`

func insertUser(t *testing.T, pool *pgxpool.Pool, email string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), schemaUserInsert, email).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestDomainsSchema checks the migration-level invariants B2 relies on:
// pending claims can pile up on one hostname, exactly one is ever verified,
// one origin per domain, and deleting a domain takes its origin with it.
// TestDomainsCRUD — claim/list/get/delete with the ownership 404 rule and
// the add-same-hostname dedupe ("adding a hostname you hold returns the
// existing claim").
func TestDomainsCRUD(t *testing.T) {
	pool := testPool(t)
	aEmail := "dom-a-crud@x.test"
	a := signupVerify(t, pool, aEmail, "secretpw123")
	b := unfollow(a)
	b.must("POST", "/auth/signup", `{"email":"dom-b-crud@x.test","password":"secretpw123"}`, http.StatusOK)
	b.must("POST", "/auth/verify", `{"token":"`+lastEmailToken(t, pool, "verify")+`"}`, http.StatusOK)

	body := a.must("POST", "/v1/domains", `{"hostname":"shop.Example.com."}`, http.StatusCreated)
	var created struct {
		Domain   domainRow `json:"domain"`
		Existing bool      `json:"existing"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("claim json: %v: %s", err, body)
	}
	if created.Domain.Hostname != "shop.example.com" || created.Domain.Status != "pending" {
		t.Fatalf("claim normalized: %+v", created.Domain)
	}
	// re-add: same row, HTTP 200, existing flag
	body = a.must("POST", "/v1/domains", `{"hostname":"shop.example.com"}`, http.StatusOK)
	var again struct {
		Domain   domainRow `json:"domain"`
		Existing bool      `json:"existing"`
	}
	if err := json.Unmarshal([]byte(body), &again); err != nil {
		t.Fatalf("re-claim json: %v", err)
	}
	if !again.Existing || again.Domain.ID != created.Domain.ID || again.Domain.Status != "pending" {
		t.Fatalf("re-claim must return the held claim: %+v vs %+v", again, created)
	}

	// list mine
	body = a.must("GET", "/v1/domains", "", http.StatusOK)
	if !strings.Contains(body, "shop.example.com") {
		t.Fatalf("list does not show the claim: %s", body)
	}
	// get mine / foreign
	a.must("GET", "/v1/domains/"+created.Domain.ID, "", http.StatusOK)
	if code, _ := b.do("GET", "/v1/domains/"+created.Domain.ID, ""); code != http.StatusNotFound {
		t.Fatalf("foreign get: want 404, got %d", code)
	}
	// b's list is empty
	if l := b.must("GET", "/v1/domains", "", http.StatusOK); strings.Contains(l, "shop.example.com") {
		t.Fatalf("b leaks a's domain: %s", l)
	}
	// instructions
	verif := a.must("GET", "/v1/domains/"+created.Domain.ID+"/verification", "", http.StatusOK)
	if !strings.Contains(verif, `"record_name":"_gatepost-verify.shop.example.com"`) ||
		!strings.Contains(verif, "gatepost-verify=") {
		t.Fatalf("instructions shape: %s", verif)
	}
	if code, v := b.do("GET", "/v1/domains/"+created.Domain.ID+"/verification", ""); code != http.StatusNotFound || strings.Contains(v, "gatepost-verify") {
		t.Fatalf("foreign verification: %d %s", code, v)
	}
	// delete: owner 200, foreign 404, then gone
	if code, _ := b.do("DELETE", "/v1/domains/"+created.Domain.ID, ""); code != http.StatusNotFound {
		t.Fatalf("foreign delete: want 404, got %d", code)
	}
	a.must("DELETE", "/v1/domains/"+created.Domain.ID, "", http.StatusOK)
	if code, _ := a.do("GET", "/v1/domains/"+created.Domain.ID, ""); code != http.StatusNotFound {
		t.Fatalf("deleted still present: %d", code)
	}
}

// TestDomainCaps — per-user quotas: GP_DOMAIN_MAX counts active claims,
// GP_DOMAIN_PENDING counts pending ones. SQL drives the statuses (no
// sleeps, live rows).
func TestDomainCaps(t *testing.T) {
	pool := testPool(t)
	c, _ := newTestServer(t, pool, func(cfg *Config) {
		cfg.DomainMaxTotal, cfg.DomainMaxPending = 2, 2
	})
	c.must("POST", "/auth/signup", `{"email":"cap@x.test","password":"secretpw123"}`, http.StatusOK)
	c.must("POST", "/auth/verify", `{"token":"`+lastEmailToken(t, pool, "verify")+`"}`, http.StatusOK)
	claim := func(host string) (int, string) {
		return c.do("POST", "/v1/domains", `{"hostname":"`+host+`"}`)
	}
	d1, _ := claim("d-1.example.com")
	d2, _ := claim("d-2.example.com")
	if code, _ := claim("d-3.example.com"); code != http.StatusUnprocessableEntity {
		t.Fatalf("pending cap (2): want 422, got %d", code)
	}
	// verify one → it still counts toward TOTAL (2 active) but frees pending
	execSQL(t, pool, `UPDATE domains SET status='verified', verified_at=now()
		WHERE hostname IN ('d-1.example.com','d-2.example.com')`)
	if code, _ := claim("d-3.example.com"); code != http.StatusUnprocessableEntity {
		t.Fatalf("total cap (2, both verified): want 422, got %d", code)
	}
	// disable a claim → same active bucket (disabled counts toward total)
	execSQL(t, pool, `UPDATE domains SET status='disabled' WHERE hostname='d-2.example.com'`)
	if code, _ := claim("d-3.example.com"); code != http.StatusUnprocessableEntity {
		t.Fatalf("disabled must still count toward the total cap: %d", code)
	}
	// freeing a claim entirely (rejected) frees the slot
	execSQL(t, pool, `UPDATE domains SET status='rejected' WHERE hostname='d-2.example.com'`)
	if code, _ := claim("d-3.example.com"); code != http.StatusCreated {
		t.Fatalf("rejected must not count: got %d", code)
	}
	_ = d1
	_ = d2
}

// TestDomainsSchema checks the migration-level invariants B2 relies on:}

// TestDomainClaimExpiry — a claim past its expires_at becomes expired (the
// live hourly job): then re-claiming revives the row with a fresh TTL.
func TestDomainClaimExpiry(t *testing.T) {
	pool := testPool(t)
	c, srv := newTestServer(t, pool)
	c.must("POST", "/auth/signup", `{"email":"lag@x.test","password":"secretpw123"}`, http.StatusOK)
	c.must("POST", "/auth/verify", `{"token":"`+lastEmailToken(t, pool, "verify")+`"}`, http.StatusOK)
	body := c.must("POST", "/v1/domains", `{"hostname":"lag.example.com"}`, http.StatusCreated)
	var d struct {
		Domain domainRow `json:"domain"`
	}
	json.Unmarshal([]byte(body), &d) //nolint:errcheck
	execSQL(t, pool, `UPDATE domains SET expires_at = now() - interval '1 minute'`)

	if n, err := srv.ExpireDomainClaims(context.Background()); err != nil || n != 1 {
		t.Fatalf("expire: n=%d err=%v", n, err)
	}
	if got := c.must("GET", "/v1/domains/"+d.Domain.ID, "", http.StatusOK); !strings.Contains(got, `"status":"expired"`) {
		t.Fatalf("claim not expired: %s", got)
	}
	// re-claim revives the same row: pending again, fresh token TTL
	body2 := c.must("POST", "/v1/domains", `{"hostname":"lag.example.com"}`, http.StatusOK)
	var again struct {
		Domain   domainRow `json:"domain"`
		Existing bool      `json:"existing"`
	}
	if err := json.Unmarshal([]byte(body2), &again); err != nil {
		t.Fatal(err)
	}
	if !again.Existing || again.Domain.ID != d.Domain.ID || again.Domain.Status != "pending" {
		t.Fatalf("revived claim: %+v", again.Domain)
	}
}

// TestDomainsSchema checks the migration-level invariants B2 relies on:
// pending claims can pile up on one hostname, exactly one is ever verified,
// one origin per domain, and deleting a domain takes its origin with it.
func TestDomainsSchema(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	u1 := insertUser(t, pool, "dom1@x.test")
	u2 := insertUser(t, pool, "dom2@x.test")

	claim := func(user string) string {
		var id string
		if err := pool.QueryRow(ctx, `INSERT INTO domains
				(owner_user_id, hostname, verify_token) VALUES ($1, 'shop.example.com', 'tok-'||$2)
				RETURNING id::text`, user, user).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	id1, id2 := claim(u1), claim(u2)
	if id1 == id2 {
		t.Fatal("claim ids must differ")
	}

	// many pending claims on one hostname: allowed (two made above)
	// but the same user cannot hold the same hostname twice
	if _, err := pool.Exec(ctx, `INSERT INTO domains (owner_user_id, hostname, verify_token)
		VALUES ($1, 'shop.example.com', 'dup')`, u1); !uniqueViolation(err) {
		t.Fatalf("re-claim by same user must fail on (owner, hostname) unique: %v", err)
	}

	// exactly one verified claim per hostname
	for i, uid := range []string{u1, u2} {
		_, err := pool.Exec(ctx, `UPDATE domains SET status='verified', verified_at = now()
			WHERE owner_user_id = $1`, uid)
		if i == 0 && err != nil {
			t.Fatalf("first verify of a hostname must succeed: %v", err)
		}
		if i == 1 && !uniqueViolation(err) {
			t.Fatalf("second verify must violate the partial unique index: %v", err)
		}
	}

	// one origin per domain
	if _, err := pool.Exec(ctx, `INSERT INTO origins (domain_id, scheme, address, port)
		VALUES ($1, 'https', 'example.org', 443)`, id1); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO origins (domain_id, scheme, address, port)
		VALUES ($1, 'https', 'example.org', 443)`, id1); !uniqueViolation(err) {
		t.Fatalf("second origin for a domain must violate UNIQUE(domain_id): %v", err)
	}

	// deleting the domain removes its origin (and claims) with it
	if _, err := pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, id1); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM origins WHERE domain_id = $1`, id1).Scan(&n); err != nil || n != 0 {
		t.Fatalf("origin survived domain delete: n=%d err=%v", n, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM domains WHERE hostname = 'shop.example.com'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("one claim should remain after delete: n=%d err=%v", n, err)
	}
}

func uniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}
