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

	"gatepost/internal/snapshot"
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
}

type caddyConfig struct {
	Admin caddyAdmin `json:"admin"`
	Apps  caddyApps  `json:"apps"`
}

type caddyAdmin struct {
	Listen string `json:"listen"`
}

type caddyApps struct {
	HTTP caddyHTTPApp `json:"http"`
	TLS  *caddyTLSApp `json:"tls,omitempty"`
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
	ServerName         string `json:"server_name,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
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
	Certificates *caddyAutomate  `json:"certificates,omitempty"`
	Automation   caddyAutomation `json:"automation,omitempty"`
}

type caddyAutomate struct {
	Automate []string `json:"automate"`
}

type caddyAutomation struct {
	Policies []caddyAutomationPolicy `json:"policies"`
}

// Issuers module "internal": the edge signs every site certificate (and the
// fallback) itself; there is no ACME phase in this project.
type caddyAutomationPolicy struct {
	Issuers []caddyIssuer `json:"issuers"`
}

type caddyIssuer struct {
	Module string `json:"module"`
}

// originKey identifies one tunnelled origin: scheme, canonical address and
// port. Two domains proxying to the same origin share one forwarder port.
func originKey(o snapshot.Origin) string {
	return fmt.Sprintf("%s://%s:%d", o.Scheme, strings.ToLower(o.Address), o.Port)
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

	domains := []snapshot.Domain(nil)
	if d != nil {
		domains = append(domains, d.Domains...) // copy: never sort the caller's slice
	}
	sort.Slice(domains, func(i, j int) bool { return domains[i].Hostname < domains[j].Hostname })

	routes := make([]caddyRoute, 0, len(domains)+1)
	for _, dm := range domains {
		port, ok := p.EgressPorts[originKey(dm.Origin)]
		if !ok {
			return nil, fmt.Errorf("caddygen: no egress port for %s (host %s)", originKey(dm.Origin), dm.Hostname)
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
			rp.Transport = &caddyTransport{
				Protocol:    "http",
				DialTimeout: originDialTimeout,
				TLS: &caddyTransTLS{
					ServerName:         strings.ToLower(dm.Origin.Address), // SNI = the origin's name
					InsecureSkipVerify: !dm.Origin.TLSVerify,
				},
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
		routes = append(routes, caddyRoute{
			Match: []caddyHostMatch{{Host: []string{dm.Hostname}}},
			Handle: []any{
				requestBodyHandler{Handler: "request_body", MaxSize: maxBodyBytes},
				rp,
			},
		})
	}
	// Catch-all LAST: every Host the routes above do not claim — and every
	// TLS handshake completed via the fallback cert — answers 421.
	routes = append(routes, caddyRoute{
		Handle: []any{staticResponseHandler{
			Handler:    "static_response",
			StatusCode: "421",
			Body:       "Misdirected Request",
		}},
	})
	srv.Routes = routes

	httpPort, httpsPort, err := portsOf(httpAddr, httpsAddr)
	if err != nil {
		return nil, err
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
			TLS: &caddyTLSApp{
				Certificates: &caddyAutomate{Automate: []string{fallbackSubject}},
				Automation: caddyAutomation{
					Policies: []caddyAutomationPolicy{{Issuers: []caddyIssuer{{Module: "internal"}}}},
				},
			},
		},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return b, nil
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
