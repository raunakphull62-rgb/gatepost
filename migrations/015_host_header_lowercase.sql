-- 015: host_header normalization. The API now lowercases host_header on write
-- (internal/server/origins.go) and only accepts LDH hostname or
-- hostname:port (ValidateHostHeader). A stored host_header is emitted
-- verbatim as the upstream Host header, so it must carry no structure.
--
-- Backfill existing data: lowercase every stored host_header, then set to
-- NULL any value that is still not a valid hostname[:port] — LDH labels,
-- each <= 63 octets, host <= 253 octets, optional :port 1..65535.
UPDATE origins
SET host_header = lower(host_header)
WHERE host_header IS NOT NULL;

UPDATE origins
SET host_header = NULL
WHERE host_header IS NOT NULL
  AND (
    host_header !~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(:[0-9]+)?$'
    OR length(host_header) > 253
    OR (
      host_header LIKE '%:%'
      AND (
        split_part(host_header, ':', 2) !~ '^[0-9]+$'
        OR split_part(host_header, ':', 2)::int < 1
        OR split_part(host_header, ':', 2)::int > 65535
      )
    )
  );
