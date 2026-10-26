// Caddy config generation (B3b item 3). ONE pure function turns a verified
// snapshot document into the JSON that is pushed to Caddy's admin /load API.
// Structured JSON only — never a text template — so every string a hostile
// hostname or origin can own is a single JSON string value: it cannot splice
// itself into a second key, route or handler. Everything the config needs
// beyond the snapshot (listen addrs, admin addr, the forwarder's ports per
// origin) arrives in CaddyParams, so Generate is deterministic and free of
// hidden state: same document in, same bytes out.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"gatepost/internal/domains"
	"gatepost/internal/snapshot"
)

// Issuer names accepted by GP_EDGE_ISSUER. Staging is the DEFAULT: a missing
// or empty setting must never burn production Let's Encrypt rate limits.
const (
	issuerStaging    = "staging"
	issuerInternal   = "internal"
	issuerProduction = "production"

	stagingDirectory    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	productionDirectory = "https://acme-v02.api.letsencrypt.org/directory"
)

// fallbackSubject is the hostname the edge keeps one managed internal
// certificate for. tls_connection_policies.fallback_sni hands it out to
// any TLS ClientHello whose SNI matches no managed site, so unknown hosts
// complete the handshake and then receive the catch-all 421 instead of a
// connection reset.
const fallbackSubject = "edge.invalid"

// Sensible limits (requirement 6): header size, body size and the
// connect/read/write timeouts on both client-facing server and origin
// transport. Values are deliberate and plain: 16 KiB headers, 32 MiB
// bodies, bounded reads/writes, bounded dials.
const (
	maxHeaderBytes          = 16 << 10 // 16 KiB
	maxBodyBytes      int64 = 32 << 20 // 32 MiB
	headerTimeout           = "10s"    // time to receive the request headers
	readTimeout             = "60s"    // read the request incl. the 32 MiB budget
	writeTimeout            = "60s"    // write the response
	idleTimeout             = "2m"     // keep-alive idling between requests
	originDialTimeout       = "10s"    // connect to the origin via the forwarder
)

// CaddyParams is the part of the config that is WIRING rather than snapshot
// content: where the server listens, where the admin API lives and which
// local egress port tunnels each origin (allocations owned by the forwarder
// in egress.go, passed in so this function stays pure).
type CaddyParams struct {
	HTTPAddr    string         // listen addr for HTTP ("" → ":80")
	HTTPSAddr   string         // listen addr for HTTPS ("" → ":443")
	AdminAddr   string         // host:port of the admin API ("" → "127.0.0.1:2019")
	EgressPorts map[string]int // originKey → local forwarder port for /load dials

	// AskURL is the poller's loopback on-demand permission endpoint. Caddy
	// calls it before issuing a certificate; anything but 200 denies. It is
	// REQUIRED once the document has at least one valid site hostname: an
	// on-demand policy without the local ask would be an open certificate
	// mint.
	AskURL string
	// Issuer is staging (default), internal, or production. Only an explicit
	// GP_EDGE_ISSUER=production opts into production Let's Encrypt.
	Issuer string

	// AccessLogPath is where the edge writes its JSON access logs ("" =
	// access logging off). The path lives on the edge's own data volume;
	// the poller only names it in every generated config.
	AccessLogPath string
}

type caddyConfig struct {
	Admin   caddyAdmin    `json:"admin"`
	Apps    caddyApps     `json:"apps"`
	Logging *caddyLogging `json:"logging,omitempty"`
}

type caddyAdmin struct {
	Listen string `json:"listen"`
}

type caddyApps struct {
	HTTP caddyHTTPApp `json:"http"`
	TLS  *caddyTLSApp `json:"tls,omitempty"`
	PKI  *caddyPKIApp `json:"pki,omitempty"`
}

type caddyHTTPApp struct {
	HTTPPort  int                    `json:"http_port,omitempty"`
	HTTPSPort int                    `json:"https_port,omitempty"`
	Servers   map[string]caddyServer `json:"servers"`
}

type caddyServer struct {
	Listen          []string          `json:"listen"`
	Protocols       []string          `json:"protocols"` // h1 h2 — h3 stays off
	AutomaticHTTPS  *caddyAutoHTTPS   `json:"automatic_https"`
	HeaderTimeout   string            `json:"read_header_timeout,omitempty"`
	ReadTimeout     string            `json:"read_timeout,omitempty"`
	WriteTimeout    string            `json:"write_timeout,omitempty"`
	IdleTimeout     string            `json:"idle_timeout,omitempty"`
	MaxHeaderBytes  int               `json:"max_header_bytes,omitempty"`
	Logs            *caddyServerLogs  `json:"logs,omitempty"` // {} = request access logs on
	TLSConnPolicies []caddyConnPolicy `json:"tls_connection_policies,omitempty"`
	Routes          []caddyRoute      `json:"routes"`
}

type caddyAutoHTTPS struct {
	DisableRedirects bool `json:"disable_redirects"`
}

// fallback_sni serves the edge's managed fallback certificate to any
// ClientHello the certificate list does not cover (unknown host).
type caddyConnPolicy struct {
	FallbackSNI string `json:"fallback_sni,omitempty"`
}

type caddyRoute struct {
	Match  []caddyHostMatch `json:"match,omitempty"`
	Handle []any            `json:"handle"`
}

type caddyHostMatch struct {
	Host []string `json:"host"`
}

type requestBodyHandler struct {
	Handler string `json:"handler"` // "request_body"
	MaxSize int64  `json:"max_size"`
}

type reverseProxyHandler struct {
	Handler   string          `json:"handler"` // "reverse_proxy"
	Upstreams []caddyUpstream `json:"upstreams"`
	Transport *caddyTransport `json:"transport,omitempty"`
	Headers   *caddyRPHeaders `json:"headers,omitempty"`
}

type caddyUpstream struct {
	Dial string `json:"dial"`
}

type caddyTransport struct {
	Protocol    string         `json:"protocol"` // "http"
	DialTimeout string         `json:"dial_timeout,omitempty"`
	TLS         *caddyTransTLS `json:"tls,omitempty"`
}

type caddyTransTLS struct {
	ServerName string `json:"server_name,omitempty"`
}

type caddyRPHeaders struct {
	Request struct {
		Set map[string][]string `json:"set,omitempty"`
	} `json:"request"`
}

type staticResponseHandler struct {
	Handler    string `json:"handler"` // "static_response"
	StatusCode string `json:"status_code"`
	Body       string `json:"body,omitempty"`
}

type caddyTLSApp struct {
	Certificates *caddyAutomate   `json:"certificates,omitempty"`
	Automation   *caddyAutomation `json:"automation,omitempty"`
}

type caddyAutomate struct {
	Automate []string `json:"automate"`
}

type caddyAutomation struct {
	OnDemand *caddyOnDemand          `json:"on_demand,omitempty"`
	Policies []caddyAutomationPolicy `json:"policies,omitempty"`
}

// caddyOnDemand: the permission module Caddy asks before minting a
// certificate. Module "http" GETs endpoint?domain=<sni>; 200 allows, every
// other status (or no answer) denies.
type caddyOnDemand struct {
	Permission caddyPermission `json:"permission"`
}

type caddyPermission struct {
	Module   string `json:"module"` // "http"
	Endpoint string `json:"endpoint"`
}

// caddyAutomationPolicy: explicit subjects are load-bearing. A default
// (subject-less) on-demand policy matches EVERY SNI, and when the ask denies
// Caddy aborts the handshake before the fallback certificate can answer 421
// (probed against 2.11.7). Scoping the policy to the snapshot's hostnames
// keeps unknown SNI on the fallback cert while still gating the known ones
// through the ask.
type caddyAutomationPolicy struct {
	Subjects []string      `json:"subjects,omitempty"`
	Issuers  []caddyIssuer `json:"issuers"`
	OnDemand bool          `json:"on_demand,omitempty"`
}

type caddyIssuer struct {
	Module string `json:"module"`
	CA     string `json:"ca,omitempty"` // ACME directory; empty for internal
}

// caddyPKIApp keeps Caddy's internal CA out of the host trust store. Nothing
// outside this node trusts the edge's internal certs, and dev/test runs must
// not mutate the machine they run on.
type caddyPKIApp struct {
	CertificateAuthorities map[string]caddyCA `json:"certificate_authorities"`
}

type caddyCA struct {
	InstallTrust *bool `json:"install_trust,omitempty"`
}

// originKey identifies one tunnelled origin: scheme, canonical address and
// port. Two domains proxying to the same origin share one forwarder port.
func originKey(o snapshot.Origin) string {
	return fmt.Sprintf("%s://%s:%d", o.Scheme, strings.ToLower(o.Address), o.Port)
}

// ---- access logging (B3b item 6) --------------------------------------------
//
// One JSON line per request to LogPath, via caddy's own pieces — no code on
// the edge beyond config: the file writer rolls so the disk cannot fill, the
// `filter` encoder deletes the credential headers BY NAME (an unattended
// marker would leak nothing, but "never log" is stricter than "never leak"),
// and per-route `log_append` middlewares add the fields caddy's default log
// lacks: request_id (caddy's per-request uuid — generated lazily and cached
// per request), path (the URI path sans query; the hostile part of the URL
// stayed a single JSON string value in item 3, and it stays one here — zap's
// JSON encoder escapes it, so a newline in a path cannot forge a new line)
// and origin (the vars handler stamps each site's origin identity; log_append
// reads it back on the way up). Authorization bodies are never in access
// logs; nothing asks for {http.request.body}.

type caddyServerLogs struct{} // {} = log to the default logger via server.Logs

type caddyLogging struct {
	Logs map[string]caddyCustomLog `json:"logs,omitempty"`
}

type caddyCustomLog struct {
	// Include pins WHICH logger feeds this custom log by name prefix: the
	// server access logger is "http.log.access" (the http app's logger, a
	// Named("log.access")). Without it the custom core would accept every
	// entry caddy produces — runtime lines (admin.api, tls) would flood the
	// access file. The key must not be "default": that is caddy's GLOBAL
	// runtime logger, and defining it redirects stderr into the access file.
	Include []string               `json:"include,omitempty"`
	Writer  *caddyLogWriter        `json:"writer,omitempty"`
	Encoder *caddyLogFilterEncoder `json:"encoder,omitempty"`
}

// caddyLogWriter: caddy's file writer. Rolling is on by default; size + keep
// are pinned so the file can never grow unbounded.
type caddyLogWriter struct {
	Output     string `json:"output"` // "file"
	Filename   string `json:"filename"`
	RollSizeMB int    `json:"roll_size_mb,omitempty"`
	RollKeep   int    `json:"roll_keep,omitempty"`
}

// caddyLogFilterEncoder wraps the json encoder and deletes whole fields.
// Nested fields use `>` paths (caddy docs: for {"a":{"b":0}}, "a>b").
type caddyLogFilterEncoder struct {
	Format string                         `json:"format"` // "filter"
	Wrap   *caddyLogJSONEncoder           `json:"wrap,omitempty"`
	Fields map[string]caddyLogFieldDelete `json:"fields,omitempty"`
}

type caddyLogJSONEncoder struct {
	Format string `json:"format"` // "json"
}

// caddyLogFieldDelete: the only filter this config uses — remove the field.
type caddyLogFieldDelete struct {
	Filter string `json:"filter"` // "delete"
}

// logAppendHandler: caddy's "log_append" middleware — one access-log field
// per instance. Value may be a placeholder (resolved when the log is written,
// so late values still work) or, without braces, a NAME IN the request's vars
// map — which is how the origin identity stamped by the vars handler lands.
type logAppendHandler struct {
	Handler string `json:"handler"` // "log_append"
	Key     string `json:"key"`
	Value   string `json:"value,omitempty"`
}

const originVar = "gatepost_origin"

// accessLogPaths: every path the filter encoder deletes, and why. Proxy-
// Authorization rides along: caddy already treats it as a credential.
func accessLogDeletes() map[string]caddyLogFieldDelete {
	return map[string]caddyLogFieldDelete{
		"uuid":                                {Filter: "delete"}, // caddy auto-adds `uuid` when the placeholder is referenced; request_id is the named duplicate
		"request>headers>Authorization":       {Filter: "delete"},
		"request>headers>Proxy-Authorization": {Filter: "delete"},
		"request>headers>Cookie":              {Filter: "delete"},
		"resp_headers>Set-Cookie":             {Filter: "delete"},
		"resp_headers>Proxy-Authorization":    {Filter: "delete"},
	}
}

// logAppendsOnce: the log_append middlewares common to every route when
// access logging is enabled.
func logAppendsOnce(originValue string) []any {
	return []any{
		logAppendHandler{Handler: "log_append", Key: "request_id", Value: "{http.request.uuid}"},
		logAppendHandler{Handler: "log_append", Key: "path", Value: "{http.request.uri.path}"},
		logAppendHandler{Handler: "log_append", Key: "origin", Value: originValue},
	}
}

// Generate is the single source of truth of every site config the edge
// serves. A nil (or domain-less) document produces the deny-all shape: both
// listeners and only the catch-all 421 route.
func Generate(d *snapshot.Document, p CaddyParams) ([]byte, error) {
	httpAddr := firstNonEmpty(p.HTTPAddr, ":80")
	httpsAddr := firstNonEmpty(p.HTTPSAddr, ":443")
	admin := firstNonEmpty(p.AdminAddr, "127.0.0.1:2019")

	srv := caddyServer{
		Listen:          []string{httpAddr, httpsAddr},
		Protocols:       []string{"h1", "h2"},
		AutomaticHTTPS:  &caddyAutoHTTPS{DisableRedirects: true}, // serve, don't 308
		HeaderTimeout:   headerTimeout,
		ReadTimeout:     readTimeout,
		WriteTimeout:    writeTimeout,
		IdleTimeout:     idleTimeout,
		MaxHeaderBytes:  maxHeaderBytes,
		TLSConnPolicies: []caddyConnPolicy{{FallbackSNI: fallbackSubject}},
	}

	doms := []snapshot.Domain(nil)
	if d != nil {
		doms = append(doms, d.Domains...) // copy: never sort the caller's slice
	}
	sort.Slice(doms, func(i, j int) bool { return doms[i].Hostname < doms[j].Hostname })

	routes := make([]caddyRoute, 0, len(doms)+1)
	logged := p.AccessLogPath != ""
	for _, dm := range doms {
		port, ok := p.EgressPorts[originKey(dm.Origin)]
		if !ok {
			return nil, fmt.Errorf("caddygen: no egress port for %s (host %s)", originKey(dm.Origin), dm.Hostname)
		}
		// handle: request_body first (bounds the body before anything else
		// sees it), then — when logging is on — the vars stamp for the
		// origin identity and the extra log fields. Each log_append runs on
		// the way back up after the proxy, exactly where its values exist.
		handle := make([]any, 0, 6)
		if logged {
			handle = append(handle, map[string]any{
				"handler": "vars",
				originVar: originKey(dm.Origin), // the vars handler is a plain map spread
			})
		}
		handle = append(handle, requestBodyHandler{Handler: "request_body", MaxSize: maxBodyBytes})
		if logged {
			handle = append(handle, logAppendsOnce(originVar)...)
		}
		rp := reverseProxyHandler{
			Handler: "reverse_proxy",
			Upstreams: []caddyUpstream{{
				Dial: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), // the tunnel, never the origin itself
			}},
		}
		switch dm.Origin.Scheme {
		case "http":
			rp.Transport = &caddyTransport{Protocol: "http", DialTimeout: originDialTimeout}
		case "https":
			// The edge ALWAYS verifies the origin certificate against the
			// origin's real name (SNI = the configured address). A snapshot
			// that asks for tls_verify=false is refused, not downgraded:
			// silently skipping verification would let anyone on the path
			// impersonate the origin. TLSVerify remains an API-side health
			// check convenience only.
			if !dm.Origin.TLSVerify {
				return nil, fmt.Errorf("caddygen: https origin %s of %s has tls_verify=false — the edge never skips origin certificate verification", originKey(dm.Origin), dm.Hostname)
			}
			rp.Transport = &caddyTransport{
				Protocol:    "http",
				DialTimeout: originDialTimeout,
				TLS:         &caddyTransTLS{ServerName: strings.ToLower(dm.Origin.Address)},
			}
		default:
			return nil, fmt.Errorf("caddygen: origin scheme %q of %s is not http(s)", dm.Origin.Scheme, dm.Hostname)
		}
		switch {
		case dm.Origin.HostHeader != nil && *dm.Origin.HostHeader != "":
			rp.Headers = &caddyRPHeaders{}
			rp.Headers.Request.Set = map[string][]string{"Host": {*dm.Origin.HostHeader}}
		case dm.Origin.Scheme == "https":
			// Caddy 2.11.7 injects Host={upstream dial address} for every TLS
			// transport (httptransport.RequestHeaderOps) — without this pin,
			// the origin would see 127.0.0.1:<tunnel port>. Explicit user
			// header ops apply after transport ops, so the public hostname wins.
			rp.Headers = &caddyRPHeaders{}
			rp.Headers.Request.Set = map[string][]string{"Host": {dm.Hostname}}
		}
		handle = append(handle, rp)
		routes = append(routes, caddyRoute{
			Match:  []caddyHostMatch{{Host: []string{dm.Hostname}}},
			Handle: handle,
		})
	}
	// Catch-all LAST: every Host the routes above do not claim — and every
	// TLS handshake completed via the fallback cert — answers 421. With
	// logging on, its lines carry origin "-" (no origin is reached).
	catch := make([]any, 0, 4)
	if logged {
		catch = append(catch, logAppendsOnce("-")...)
	}
	catch = append(catch, staticResponseHandler{
		Handler:    "static_response",
		StatusCode: "421",
		Body:       "Misdirected Request",
	})
	routes = append(routes, caddyRoute{Handle: catch})
	srv.Routes = routes
	if logged {
		srv.Logs = &caddyServerLogs{}
	}

	httpPort, httpsPort, err := portsOf(httpAddr, httpsAddr)
	if err != nil {
		return nil, err
	}
	siteIssuer, err := issuerConfig(p.Issuer)
	if err != nil {
		return nil, err
	}
	// Unknown-SNI TLS still terminates on the fallback cert (item 3's 421),
	// so the fallback is always issued internally and kept out of the host
	// trust store.
	installTrust := false
	tlsApp := &caddyTLSApp{
		Certificates: &caddyAutomate{Automate: []string{fallbackSubject}},
		Automation: &caddyAutomation{
			Policies: []caddyAutomationPolicy{{
				Subjects: []string{fallbackSubject},
				Issuers:  []caddyIssuer{{Module: "internal"}},
			}},
		},
	}
	if subjects := onDemandSubjects(doms); len(subjects) > 0 {
		if p.AskURL == "" {
			return nil, fmt.Errorf("caddygen: %d site hostname(s) but no AskURL — refusing an on-demand policy without the local ask gate", len(subjects))
		}
		tlsApp.Automation.OnDemand = &caddyOnDemand{Permission: caddyPermission{
			Module:   "http",
			Endpoint: p.AskURL,
		}}
		tlsApp.Automation.Policies = append(tlsApp.Automation.Policies, caddyAutomationPolicy{
			Subjects: subjects,
			Issuers:  []caddyIssuer{siteIssuer},
			OnDemand: true,
		})
	}
	cfg := caddyConfig{
		Admin: caddyAdmin{Listen: admin},
		Apps: caddyApps{
			HTTP: caddyHTTPApp{
				// http_port/https_port only deviate from caddy's defaults so
				// e2e (high ports) keeps automatic_https's port roles right.
				HTTPPort:  httpPort,
				HTTPSPort: httpsPort,
				Servers:   map[string]caddyServer{"edge": srv},
			},
			TLS: tlsApp,
			PKI: &caddyPKIApp{CertificateAuthorities: map[string]caddyCA{
				"local": {InstallTrust: &installTrust},
			}},
		},
		Logging: accessLogging(p.AccessLogPath),
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return b, nil
}

// accessLogging: the logging app the /load config carries — nil when the
// path is empty (access logging off). One log, "default": rolled file writer
// + the filter-wrapped json encoder that strips credentials by name.
func accessLogging(path string) *caddyLogging {
	if path == "" {
		return nil
	}
	return &caddyLogging{Logs: map[string]caddyCustomLog{
		"http.log.access": {
			Include: []string{"http.log.access"}, // nothing but access lines
			Writer: &caddyLogWriter{
				Output:     "file",
				Filename:   path,
				RollSizeMB: 10,
				RollKeep:   5,
			},
			Encoder: &caddyLogFilterEncoder{
				Format: "filter",
				Wrap:   &caddyLogJSONEncoder{Format: "json"},
				Fields: accessLogDeletes(),
			},
		},
	}}
}

// onDemandSubjects: the served hostnames Caddy may request a certificate
// for. Invalid names are skipped (and therefore fail closed to the fallback
// cert): the API normalizes hostnames before signing, so this only matters
// if a bad document is ever signed, and the generator must not turn it into
// unvalidated Caddy subjects. Sorted + de-duplicated for deterministic JSON.
func onDemandSubjects(doms []snapshot.Domain) []string {
	seen := map[string]struct{}{}
	for _, dm := range doms {
		h, err := domains.NormalizeHostname(dm.Hostname, nil)
		if err != nil {
			continue
		}
		seen[h] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// issuerConfig maps GP_EDGE_ISSUER to Caddy's issuer shape. The empty value
// takes staging: production must be an explicit choice.
func issuerConfig(name string) (caddyIssuer, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", issuerStaging:
		return caddyIssuer{Module: "acme", CA: stagingDirectory}, nil
	case issuerInternal:
		return caddyIssuer{Module: "internal"}, nil
	case issuerProduction:
		return caddyIssuer{Module: "acme", CA: productionDirectory}, nil
	default:
		return caddyIssuer{}, fmt.Errorf("caddygen: unknown issuer %q (want staging, internal or production)", name)
	}
}

// portsOf extracts the numeric ports for http_port/https_port; 80/443 are
// caddy's defaults, so they are reported as 0 (omitted).
func portsOf(httpAddr, httpsAddr string) (int, int, error) {
	_, hp, err := net.SplitHostPort(httpAddr)
	if err != nil {
		return 0, 0, fmt.Errorf("caddygen: bad http listen addr %q: %w", httpAddr, err)
	}
	_, sp, err := net.SplitHostPort(httpsAddr)
	if err != nil {
		return 0, 0, fmt.Errorf("caddygen: bad https listen addr %q: %w", httpsAddr, err)
	}
	httpPort, httpsPort := 0, 0
	if p, err := strconv.Atoi(hp); err == nil && p != 80 {
		httpPort = p
	}
	if p, err := strconv.Atoi(sp); err == nil && p != 443 {
		httpsPort = p
	}
	return httpPort, httpsPort, nil
}
