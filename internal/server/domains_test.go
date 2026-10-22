package server

import (
	"context"
	"errors"
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
