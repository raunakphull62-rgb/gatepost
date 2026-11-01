# Gatepost Frontend PRD (Production)

Nov 1, 2026 · @Raunak

## 1. Overview

The Gatepost frontend is a production web app, hosted on Vercel, that lets a customer put a domain behind Gatepost's edge (reverse proxy, WAF, alerts) and watch it. It is built against the existing Go control-plane API, and it is shipped as a real product, not a demo.

**Goals**

- A new user can sign up, add a domain and origin, change DNS, and see the domain protected, without help.
- A user can set the WAF mode per domain (off, detection, blocking), exclude rule IDs, and see the change history.
- Operator alerts (origin unsafe, origin unresolved, snapshot build failed, WAF config failed, node stale) reach the right person in the UI.
- Every page handles loading, empty, error, offline and expired-session states.
- Tenant isolation is never the frontend's job to enforce, but the frontend never shows or caches another tenant's data.

**Non-goals for this release**

- Billing and plans, DNS hosting UI, cache, bot and GeoIP settings, organizations and teams, analytics dashboards. The backend does not have these yet. Screens for them are not built and not faked.
- A mobile app. The web app must work well on a phone, since many users in India are mobile-first.

**What production-grade means here**

- Strict TypeScript, no `any` in app code, API types generated from a written contract.
- Accessibility to WCAG 2.2 AA, tested.
- Performance budgets (section 8) enforced in CI.
- Security headers, CSP, CSRF protection and safe session handling (section 7).
- Automated tests at three levels: unit, component, and end-to-end against a real backend.
- Error reporting, structured logs and a runbook before launch.

## 2. Users and journeys

Two kinds of users exist in v1. The customer is the main one. The operator (you, the Gatepost team) needs a small internal view, and it is built second.

| Role | What they need | In v1 |
| --- | --- | --- |
| Customer | Protect their own domains, see status, change WAF mode, see what changed | Full |
| Operator | See node health, stale nodes, snapshot build failures, WAF config failures across all tenants | Small internal console, behind an operator-only gate |

**Core journeys, in priority order**

1. **Sign up and sign in.** Email and password, plus Google and GitHub sign-in once the OAuth apps exist. A returning user lands on their domain list.
2. **Add a domain.** Enter a hostname, prove ownership with a TXT record, set the origin and test the connection, then follow the traffic DNS instructions. A 422 from the backend because of the snapshot size limit must show a clear "we cannot add more domains right now" message, not a generic error.
3. **Wait for protection to go live.** The domain shows the backend's statuses (pending, verified, rejected, expired, disabled). The UI polls, shows what is still pending (ownership proof, origin), and never claims "protected" until the backend says so.
4. **Set the WAF mode.** Per domain: off, detection or blocking. Optional excluded rule IDs (integers 1 to 999999). The UI explains what each mode does and that detection logs without blocking. A change shows who, when, and from what to what.
5. **Read alerts.** Origin unsafe, origin unresolved, and any alert tied to the user's domains, with clear next steps. Resolved alerts move to history.
6. **See change history.** For each domain, the trail of WAF changes (time, actor, before, after).
7. **Delete a domain.** Typed-name confirmation, because it removes protection.

**Operator journeys (second wave).** Open the console, see which nodes are stale or failing, open the alerts for snapshot build failed, WAF config failed and node stale, and see which tenant and domain each belongs to.

## 3. Stack and architecture

The browser talks only to the Next.js app on Vercel. The Next.js app forwards API calls to the Go control plane, so the session cookie belongs to the app's own domain and the browser never calls the API directly. This changes one choice in the earlier Frontend and UI PRD: Next.js replaces Vite, because Vercel supports it natively and it gives server rendering for the marketing pages, route protection in middleware, and a same-origin proxy.

| Part | Choice | Why |
| --- | --- | --- |
| Framework | Next.js (App Router), current stable | Native on Vercel, server rendering, middleware, route handlers |
| Language | TypeScript, `strict: true`, `noUncheckedIndexedAccess` | Catches contract drift at build time |
| Styling | Tailwind with the design tokens, Radix primitives (shadcn/ui style) | Accessible components without a heavy library |
| Server state | TanStack Query | Caching, retries, polling, stale states |
| API types | Generated from the backend OpenAPI file with `openapi-typescript`, plus Zod validation at the boundary | One source of truth for shapes |
| Forms | React Hook Form with Zod | Same schemas for client validation |
| Tests | Vitest, Testing Library, MSW, Playwright, axe | Unit, component, contract and end-to-end |
| Errors and logs | Sentry (or equivalent) and Vercel logs | Request ID on every error |
| Package manager | pnpm, lockfile committed, exact versions pinned | Reproducible builds |

**Repo layout.** A separate repository, `gatepost-web`, so the backend release cycle and the frontend release cycle stay independent.

```
app/(marketing)/      public pages: home, pricing placeholder, docs link
app/(auth)/           sign in, sign up, reset, OAuth callback
app/(app)/            signed-in app: domains, domain detail, alerts, account
app/(operator)/       operator console, hidden unless role = operator
app/api/              BFF route handlers only where a rewrite is not enough
lib/api/              generated client, fetch wrapper, error mapping
lib/auth/             session helpers, CSRF, middleware helpers
components/ui/        design system components
components/domain/    domain-specific components
e2e/                  Playwright tests
```

**Rules**

- Server components fetch on the server only where data is needed on first paint. Interactive pages use TanStack Query on the client.
- No API URL, no secret and no token in client code. The API base URL is a server-only environment variable.
- The generated client is never edited by hand. A contract change means regenerating, and CI fails if the generated file is out of date.

## 4. Backend integration

This section is taken from the backend code (extract of commit `cef486b`, 2026-11-01), not from assumptions. Items marked **F0b** are backend changes that must land before the screens that need them.

**Topology.** The browser only talks to `https://app.<domain>`. A Next.js route handler at `/backend/*` forwards to the Go API root, so the browser calls `/backend/auth/login`, `/backend/v1/domains` and `/backend/api/me`. The API's `GP_PUBLIC_BASE_URL` is set to `https://app.<domain>/backend`, so the session cookie gets the Secure flag and the OAuth redirect URIs become `https://app.<domain>/backend/auth/oauth/google/callback` (and `github`). The proxy forwards only these path groups: `/auth/*` (except API keys), `/api/me`, `/v1/domains*`, and `/v1/nodes*` for operators. It never forwards `/node/v1/*` (edge nodes), `/api/user-data` or `/auth/api-keys*`.

**Routes the v1 UI uses**

| Route | Body in, result out | Main errors |
| --- | --- | --- |
| `POST /auth/signup` | `{email, password 8..128}` gives `200 {ok, message}`, the same for new and existing emails. No session yet | 400 invalid email or password; 429 |
| `POST /auth/verify` | `{token}` gives `200 {ok}` and sets the session cookie | 400 invalid or expired token (24 h) |
| `POST /auth/login` | `{email, password}` gives `200 {ok}` and sets the cookie | 401 invalid credentials; 429 too many requests |
| `POST /auth/logout` | none gives `200 {ok}` | 401 |
| `POST /auth/password-reset-request` | `{email}` gives `202 {ok, message}`, the same whether the email exists or not | 400 invalid email; 429 |
| `POST /auth/password-reset` | `{token, new_password}` gives `200 {ok}` and **all sessions are revoked**, so the user must sign in again | 400 invalid password / invalid or expired token (30 min) |
| `POST /auth/password-change` | `{current_password, new_password}` gives `200 {ok}`. Other sessions end, this one rotates | 401 invalid credentials; 400 invalid password |
| `GET /auth/sessions` | gives `{sessions:[{id, created_at, expires_at, current}]}` | 401 |
| `POST /auth/sessions/{id}/revoke` | gives `{ok}` | 404 not found |
| `POST /auth/logout-everywhere` | gives `{ok}` | 401 |
| `GET /auth/oauth/{google or github}/start` | `302` to the provider. Callback returns JSON `200 {ok}` today (**F0b**: redirect into the app) | 404 unknown provider (not configured); 403 oauth login failed |
| `GET /api/me` | gives `{id, email}` today (**F0b**: add `email_verified`, `is_operator`) | 401 |
| `GET /v1/domains` | gives `{domains:[domain]}`, newest first, at most 20 per user, not paginated | 401 |
| `POST /v1/domains` | `{hostname, setup_type:"cname"}` gives `201 {domain, existing:false}`, or `200 {domain, existing:true}` when the caller already holds a claim (expired or rejected claims return to pending) | 403 reserved name; 422 invalid hostname, domain cap (20), pending cap (5), snapshot size cap; 409 verified by another user; 429 |
| `GET /v1/domains/{id}` / `DELETE` | gives `{domain}` / `{ok}` | 404 not found (also for other users' domains) |
| `GET /v1/domains/{id}/verification` | gives `{verification:{domain_id, hostname, setup_type, status, expires_at, record_name, record_value}}`. The user creates a **TXT** record named `_gatepost-verify.<hostname>` with the value `gatepost-verify=<token>` | 404 |
| `POST /v1/domains/{id}/verify` | gives `{status:"verified"}`. This call is the DNS check (there is no read-only poll) | 400 verification failed (no TXT found); 410 claim expired or not verifiable; 409 contested or raced; 502 dns lookup failed; 429 |
| `POST` / `GET` / `PUT /v1/domains/{id}/origin` | `{scheme http or https, address, port, host_header?, tls_verify? (default true), health_path? (default "/"), health_interval? (10..86400, default 60)}` gives `{origin}`. POST is create (409 if one exists), PUT is update | 422 with a field prefix (see below); 404 no origin set |
| `POST /v1/domains/{id}/origin/test` | gives `{test:{reachable, status_code?, tls_ok?, duration_ms, error?}}`. **Always HTTP 200**: read `reachable` and `error` | 429 (10 per 15 min) |
| `PUT /v1/domains/{id}/waf` | `{mode: off, detection or blocking (default detection), excluded_rule_ids: [int 1..999999]}` gives `{domain}` | 400 mode / rule id out of range |
| `GET /v1/nodes`, `POST /v1/nodes`, `POST /v1/nodes/{id}/revoke` | Operator only. Node: `{id, name, role edge or dns, status active or revoked, last_seen?, applied_version?, created_at}` | 403 operator access only |

**Not in the v1 UI:** the DNS records routes (they need nameserver mode, and no Gatepost DNS server exists yet), API keys, and user-data. Hide the "nameserver" setup type entirely.

**The domain object:** `{id, hostname, status, setup_type, claimed_at, verified_at?, expires_at?, ns1, ns2, waf_mode, excluded_rule_ids[]}`. Status is one of `pending`, `verified`, `rejected`, `expired`, `disabled`. A pending claim expires after 7 days (a job flips it to `expired` hourly). `disabled` has no code path that sets it, so show it as a neutral label and nothing more. There is no "active" status.

**Errors today.** Every error is `{"error": "<text>"}` and nothing else, so the UI keys off the HTTP status and the message. Until **F0b** adds `code` and `request_id`, the client does this:

- Map each known message string to friendly copy in one messages file, and fall back to showing the server text as plain text.
- Field errors carry a prefix that names the field: `invalid hostname:` (hostname), `origin address:` (address), `port:` (port), `scheme must be` (scheme), `host_header` (host\_header), `health_path` (health\_path), `health_interval` (health\_interval), `mode must be` (mode), `rule id` (excluded\_rule\_ids), `invalid password` (new\_password), `invalid email` (email).
- 401 sends the user to sign-in with return-to. 403 and 404 on a domain show the same not-found page. 429 shows a generic wait message (the API gives no `Retry-After`, and lockout lasts up to 15 minutes). 422 with "snapshot" in the text means platform capacity: show the dedicated message.

**Limits the UI must respect.** Sign-up, sign-in, reset and password change share 100 requests per IP per 15 minutes. Sign-in locks after 5 failures per IP and email (the lock state is not reported, so say only "too many attempts, try again later"). Domain add 20, verify 20, origin test 10, per user and per IP per 15 minutes. **Saving an origin counts against the domain-add cap**, so disable the button while saving and never auto-retry.

**Polling and time.** Auto-check the TXT record by calling the verify route no more than once per 60 seconds, stop on 429, and offer a "Check now" button. Domain data refreshes when a page is focused and every 60 seconds. All timestamps are RFC 3339 in UTC, shown in the user's time zone (default Asia/Kolkata). The API does not report whether a domain's config is live on the edge nodes, so the UI never says "live" (see section 11).

## 5. Pages

Build a page only when its backend column says Ready. A page that waits on a backend item is built with that item's route mocked behind one switch and labelled in `progress.md`. Nothing is faked in the UI.

| Route | Purpose and data | Backend | Must handle |
| --- | --- | --- | --- |
| `/` | Landing page: what Gatepost is, sign-up button. Static | Ready | Fast first paint, SEO tags |
| `/legal/terms`, `/legal/privacy` | Required for OAuth review. Text supplied by you | n/a | Linked from sign-up and footer |
| `/signup` | Email and password (8 to 128 characters). Strength meter recommends 12 or more but enforces only the API's rule. After submit: "check your inbox", the same message for new and existing emails | Ready | 400, 429, double submit |
| `/verify-email` | Reads `?token=` from the email link, posts it to `/auth/verify`, then lands signed in on `/domains`. Also lets the user paste a token | Needs email links (F0b-email) | Invalid or expired token (24 h), resend by signing up again |
| `/signin` | Email and password, OAuth buttons only for configured providers | Ready (OAuth needs F0b redirect) | One generic failure message, lockout message without a time, return-to |
| `/forgot`, `/reset/[token]` | Request link (always the same answer), set new password. After reset the user signs in again, because all sessions were revoked | Ready; link needs F0b-email | Expired token (30 min) |
| `/domains` | The user's domains: hostname, status badge, WAF mode, Add button | Ready | Empty state, 20-domain cap, API down |
| `/domains/new` | Wizard in the backend's real order: (1) hostname, creates a claim; (2) **prove ownership**: show the TXT record name and value with copy buttons, "Check now" plus a 60-second auto-check; (3) **origin**: scheme, address, port, advanced options, **Test connection**; (4) WAF mode (default detection, with an explanation); (5) **point your traffic**: DNS instructions for the traffic target | Steps 1 to 4 Ready. Step 5 needs a traffic target from the API (section 11) | 403 reserved name, 422 invalid hostname or caps or capacity, 409 taken by another user, 410 claim expired (offer re-claim), unsafe origin messages shown as written, leaving and resuming |
| `/domains/[id]` | Overview: status, claim expiry for pending, origin summary, WAF mode, the TXT instructions while pending | Ready | Each status: pending, verified, rejected, expired, disabled. Wording never claims the domain is live on the edge |
| `/domains/[id]/security` | WAF mode selector with explanations, excluded rule IDs editor (integers 1 to 999999; the UI caps the list at 100 entries and asks the backend to enforce the same) | Ready | Confirm before blocking; show the saved value from the response |
| `/domains/[id]/activity` | Change history: time, who, what, before, after | Needs F0b route | Empty, pagination |
| `/domains/[id]/settings` | Edit origin (same rules as the wizard), delete with typed hostname | Ready | 404 after delete, rate-limit message on repeated saves |
| `/alerts` | Alerts for the user's domains, next-step text per kind | Needs F0b route | Open and resolved, empty |
| `/account` | Email, change password, list of sessions with revoke, "sign out everywhere" | Ready | Re-auth: wrong current password gives 401 |
| `/operator`, `/operator/nodes` | Node list: name, role, status, last seen, applied version, revoke | Ready (needs `is_operator` from F0b) | Server-side role gate; 404 for others |
| `/operator/alerts` | All alerts across tenants | Needs F0b route | Same gate |
| 404, 500, offline | System pages | n/a | No stack traces |

**Every page also needs**

- A loading state (skeleton), an empty state, an error state with retry and, once the API sends it, a copyable request ID, plus a stale-data notice when refreshing fails.
- Keyboard use for every action, visible focus, labelled fields, and errors linked to their fields.
- A layout that works from 360 px wide: cards instead of wide tables, no horizontal page scroll.
- All text in one messages file, English for v1.

**Deferred until the backend exists:** rate-limit and IP-rule tabs, traffic and security analytics, bot detection, caching, DNS record management and the nameserver setup type, team members, API keys, billing.

## 6. Design system and UX

The visual language, tokens, component list and microcopy rules already exist in the [Gatepost Frontend and UI PRD](https://claude.ai/artifact/AXnQGiMr5VhbhiDFp5U9u2) (sections Design principles, Design system, Content and microcopy). The coding agent cannot open that link, so export it as Markdown and put it in the repo as `docs/design-system.md` before the build starts. Where that document and this one disagree, this one wins.

**What this PRD adds**

- **Tokens first.** All colour, spacing, type and radius values live as CSS variables defined once, with a light and a dark theme that both pass contrast checks (4.5:1 for text). No hard-coded colours in components.
- **Components before pages.** Build and test the core set first: Button, Input, Select, Switch, Dialog, Drawer, Toast, Tabs, Table (with mobile card form), Badge, Skeleton, EmptyState, ErrorState, CopyField, ConfirmDialog (typed confirmation), StatusChecklist. Each has a story or test page showing every state.
- **Status is never colour alone.** Every status badge pairs an icon and a word with its colour.
- **Calm tone.** This is a security product. Alerts say what happened, what it means for the site, and what to do next, in plain words. No alarmist text, no jargon without a one-line explanation (for example, what "detection mode" means).
- **Show what changed.** Any setting change shows the before and after values and who made the change.
- **Dangerous actions are slow on purpose.** Switching to blocking mode asks for confirmation and states what will be blocked. Deleting a domain requires typing its name.
- **Copy buttons everywhere** for DNS values, request IDs and hostnames.

**India-first**

- Mobile first. The most common phone is a mid-range Android on a slow connection, so the first load of a signed-in page stays within the budgets in section 8.
- Time zone defaults to Asia/Kolkata, dates in a clear unambiguous format.
- All text in a messages file; Hindi and other languages can be added later. Layouts must survive text that is 40 percent longer.
- Registrar help for the DNS step covers the common Indian registrars and DNS hosts, with short written steps and no videos required.
- Later phases will add INR billing, Telegram and WhatsApp alert channels, and UPI. Leave room in settings for them, but build nothing for them now.

## 7. Security requirements

This is a security product, so the app itself must be hard to attack. Each item is a requirement with a test, not a suggestion.

**Sessions and requests**

- The session is an HttpOnly, Secure, SameSite=Lax cookie on the app's own domain, set through the same-origin proxy. No token in `localStorage`, `sessionStorage`, URLs or JavaScript-readable cookies.
- Every state-changing request carries a CSRF protection the contract defines (the API compares the Origin header against an exact-match allow-list of app origins, plus SameSite=Lax cookies). A test proves a write without it is rejected.
- Sign-out clears the cookie, the TanStack Query cache and any in-memory user data.
- The "return to" parameter after sign-in accepts only same-site relative paths. Anything else is ignored (no open redirect).

**Browser protections**

- A strict Content-Security-Policy using per-request nonces set in middleware: no `unsafe-inline` or `unsafe-eval` for scripts, `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`, and `connect-src` limited to the app's own origin and the error-reporting host.
- Headers on every response: `Strict-Transport-Security` (preload-ready), `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` that disables unused features, `Cross-Origin-Opener-Policy: same-origin`.
- Public pages and the signed-in app are tested with a CSP report-only period before enforcement.

**Content handling**

- No `dangerouslySetInnerHTML`. A lint rule fails the build if it appears.
- Any text that came from outside (hostnames, origin values, alert details, rule messages, change-trail values) is rendered as plain text and length-limited in the UI.
- Links to external sites use `rel="noopener noreferrer"`.

**Tenant isolation in the UI**

- The UI never trusts the URL to decide what the user may see. The backend decides; the UI shows "not found" for both 403 and 404 on a resource.
- Query keys include the user ID, so a cached result from one account is never shown to another after a sign-in change.
- The operator console is gated on the server (middleware plus the API role check). Hiding the menu is not enough. A non-operator gets a 404.

**Supply chain and secrets**

- Exact dependency versions, a committed lockfile, `pnpm audit` and a licence check in CI, automated update PRs, and install scripts disabled except for an explicit allow-list.
- Secrets only in Vercel environment variables, never in variables starting with `NEXT_PUBLIC_`. No secret in the repo, in chat, or in client bundles; CI scans for them.
- Source maps are uploaded to the error-reporting service and not served publicly.

**Abuse and privacy**

- Forms have double-submit protection and show the backend's rate-limit wait time. Sign-up and sign-in pages are protected from bots with a challenge if the backend supports one.
- Error reports and logs contain request IDs but not passwords, session values, full origin URLs with credentials, or email addresses in URLs.
- Cookie notice and privacy text are supplied for India's data protection rules and checked by you with a lawyer before public launch.

## 8. Quality bar

A page is not done until it meets every row below. CI enforces the ones that can be automated.

| Area | Requirement | How it is checked |
| --- | --- | --- |
| Accessibility | WCAG 2.2 AA. Full keyboard use, visible focus, labelled fields, errors tied to fields, reduced-motion respected, screen-reader names on icons | `axe` in component and Playwright tests (zero serious violations), plus a manual keyboard pass per page |
| Performance | Largest Contentful Paint 2.5 s or less, Interaction to Next Paint 200 ms or less, Cumulative Layout Shift 0.1 or less, on a mid-range Android over a slow 4G profile. First-load JavaScript for a signed-in page 170 KB gzipped or less | Lighthouse CI with these budgets as failing thresholds on preview deployments |
| Responsiveness | Works from 360 px wide up. No horizontal page scroll | Playwright at 360, 768 and 1280 px |
| Types | `strict` TypeScript, no `any`, no unchecked non-null assertions in app code | `tsc --noEmit` and ESLint in CI |
| Contract | Generated API client matches the committed OpenAPI file. Every response is validated at the boundary | CI regenerates and diffs; MSW contract tests |
| Unit and component tests | Every component state, every form validation rule, every error mapping | Vitest and Testing Library, coverage reported, no minimum number chased |
| End-to-end tests | Sign up, sign in, add a domain, see it become active, change WAF mode, see the change trail, receive and see an alert resolve, sign out, expired session | Playwright against a real backend started in CI (the Go API and Postgres), not mocks |
| Failure behaviour | API down, slow API, 401 mid-session, 422 capacity, 429, malformed response, offline | Dedicated e2e tests that make the backend misbehave |
| Observability | Error reporting with request IDs, web-vitals reporting, structured server logs | Verified in staging before launch by causing an error on purpose |
| Browser support | Last two versions of Chrome, Edge, Safari and Firefox; Samsung Internet; Android WebView not required | Playwright on Chromium, WebKit and Firefox |

**Definition of done for any change:** types pass, lint passes, tests pass, a11y checks pass, budgets hold, the preview deployment was opened and used by hand on a phone-sized screen, and the PR lists anything skipped. Nothing is reported as passing without the command output.

## 9. Deployment on Vercel

The app deploys from GitHub to one Vercel project. The Go API is hosted separately and must be reachable over public HTTPS before the frontend can go live.

| Environment | Frontend URL | API it talks to | Notes |
| --- | --- | --- | --- |
| Development | `localhost:3000` | Local API and Postgres | Seeded test data, no real accounts |
| Preview | Vercel preview URL per pull request | **Staging** API only, never production | Previews are protected by Vercel Authentication so staging data is not public |
| Production | `app.<your-domain>` (marketing at `<your-domain>`) | Production API at `api.<your-domain>` | Deploys from `main` only after required checks pass |

**Environment variables** (set in Vercel, per environment, never in the repo)

| Name | Visibility | Purpose |
| --- | --- | --- |
| `API_BASE_URL` | Server only | Where the proxy forwards requests |
| `APP_ORIGIN` | Server only | The app's public origin, used for redirects, cookies and CSRF checks |
| `SENTRY_DSN` | Public (a DSN is not secret) | Error reporting |
| `SENTRY_AUTH_TOKEN` | Build only | Uploads source maps |
| GP\_PROXY\_SECRET | Server only | Shared secret the proxy sends so the API trusts the forwarded client IP. The same random value is set on the API as GP\_TRUSTED\_PROXY\_SECRET. Never in the repo or in chat |

Commit an `.env.example` listing the names with no values, and have the app fail at startup with a clear message when a required variable is missing.

**Routing.** A route handler at `/backend/*` forwards to `API_BASE_URL`, so the browser only ever sees the app's own origin. It forwards only the allowed path groups listed in section 4, with cookies, `Origin` and `Content-Type`; strips any inbound `X-Gatepost-*` header; adds `X-Gatepost-Proxy-Secret` and `X-Gatepost-Client-IP` (taken from the header Vercel sets for the real client address; verify which one); sets a 15-second timeout and a 1 MB body cap; and passes `Set-Cookie` through unchanged. Confirm in a staging test that the session cookie reaches the browser on the app's domain. The API must be configured to trust the proxy secret and the app origin (section 11, gaps 1 and 2) before sign-in works.

**CI and release**

- GitHub Actions runs type check, lint, unit and component tests, the contract check, the end-to-end suite against the Go API and Postgres, `pnpm audit`, and Lighthouse on the preview URL.
- `main` is protected. A pull request needs all checks green and one review (you). Vercel's Git integration builds previews and deploys production.
- Rollback is Vercel's instant rollback to the previous deployment. Write this in the runbook, and practise it once before launch.
- Database or API changes that the frontend depends on ship to production first. The frontend then ships against them. Never the other way round.

**Hosting choices to confirm**

- **Plan.** Vercel's free Hobby plan is meant for personal, non-commercial use. A real product that takes customers needs a paid plan. Check Vercel's current terms before launch.
- **Region.** Put the serverless functions in the region closest to the API. If the API runs in India, use Mumbai (`bom1`) if available on your plan. If it stays in the US, use a US region.
- **API hosting.** The control plane needs a stable public HTTPS address (for example `api.<your-domain>`) with TLS, health checks and restarts. This is not set up yet (section 11).

## 10. Build plan for the coding agent

Build in phases and stop at each gate. A gate passes only with raw command output as evidence, not a summary. Each phase runs in a fresh agent session to keep the context small.

| Phase | Scope | Gate (evidence required) |
| --- | --- | --- |
| F0 Contract (backend repo) | Write `docs/api-contract.md` and `openapi.yaml` from the code: every route, auth and CSRF behaviour, the error shape, pagination, status values, and one real `curl` example each. Add a seeded test user | Each route's `curl` output pasted; OpenAPI validates; gaps listed |
| F1 Foundation | Repo `gatepost-web`, Next.js, strict TypeScript, Tailwind tokens, UI components with every state, fetch wrapper, error mapping, security headers and CSP (report-only), MSW, CI, `.env.example` | CI green; component test page; headers verified with `curl -I`; Lighthouse baseline |
| F2 Auth | Sign up, sign in, reset, verify, OAuth callbacks, session middleware, expired-session handling, return-to | E2E: sign up, sign in, expired session, wrong password, OAuth denied |
| F3 Domains | List, add-domain wizard, overview with polling, DNS instructions, 422 capacity message | E2E against the real API: add domain, see pending then active |
| F4 Security and settings | WAF mode and rule exclusions, confirm-to-block, change history (when the route exists), origin edit, delete with typed name | E2E: change mode, see the trail, delete; isolation test with two users |
| F5 Alerts and account | Alerts list with next-step text, auto-resolve display, account page, sessions | E2E: raise an origin alert in the backend, see it, see it resolve |
| F6 Operator console | Nodes, stale flag, cross-tenant alerts, server-side role gate | E2E: operator sees it, normal user gets 404 |
| F7 Hardening | Full accessibility pass, performance budgets, CSP enforced, failure-mode tests, error reporting verified, runbook | axe zero serious; Lighthouse thresholds met; failure tests green; CSP reports clean |
| F8 Release | Staging then production on Vercel, rollback drill, launch checklist | Production smoke test output; rollback performed once |

**F0b (backend work package, section 11)** runs in the backend repo while F1 is built. It must be finished and the contract copied again before F2 starts. F1 depends on none of it, because it works against mocks.

**Rules for the agent**

1. Read `docs/prd.md`, `docs/design-system.md`, `docs/api-contract.md` and `docs/progress.md` first, then confirm in one line.
2. One phase at a time. Stop at the gate and wait for "go".
3. Never invent an endpoint, a field or a status value. If the contract lacks it, stop and list it as a gap.
4. Raw command output as evidence. Say what was skipped. Do not claim a check passed without running it.
5. Commit each item separately. Never push to `main`, never deploy to production, never change Vercel settings without "go".
6. Never read or print `.env` files or secrets. Never commit a secret.
7. Keep long output short (`tail -60`). Run long jobs in the foreground.
8. No new dependency without a one-line reason, a pinned version, and a licence and audit check.

**Kickoff prompt (paste this into the first session, after adding the three docs to `docs/`)**

```
You are building the Gatepost web app, a production product, not a demo. Read docs/prd.md, docs/design-system.md and docs/api-contract.md (if it exists) in full, then reply with one line saying you have read them and list any gaps between the PRD and the contract. Follow section 10 of the PRD: work on phase F1 only, stop at its gate, and show raw evidence for every gate item. Do not invent endpoints. Do not push, deploy, or touch Vercel settings. Never read or print secrets. Commit each item separately. Then stop and wait for my "go".
```

## 11. Backend gaps and open questions

These come from reading the backend code. "F0b" is the backend work package. Items marked Blocks F2 stop sign-in from working in production; the frontend foundation (F1) does not wait for any of them.

| # | Gap | Effect on the frontend | Needed by |
| --- | --- | --- | --- |
| 1 | **Client IP behind the proxy.** The sign-in lockout and all rate limits key on the client IP. The API trusts a forwarded IP only from CIDRs listed in `GP_TRUSTED_PROXIES`, and Vercel's addresses are not a fixed list | Every user would share one IP and lock each other out. Fix (F0b-0a): the proxy sends a shared secret plus the real IP, the API trusts it only with the secret | Blocks F2 |
| 2 | **CSRF check compares Origin to the API's own host.** Through the proxy the browser's Origin is the app domain, so every write gets 403 "cross-origin request refused". Also confirm whether PATCH is covered by the guard (the code comment names POST, PUT, DELETE), and what happens with a missing Origin (today it passes) | Writes fail. Fix (F0b-0b): an exact-match origin allow-list `GP_ALLOWED_ORIGINS` | Blocks F2 |
| 3 | **Error envelope** is `{"error": text}` only: no code, no request ID | The UI maps by message text. Fix (F0b-1): add `code` and `request_id`, keep `error` | F2 |
| 4 | `GET /api/me` returns only `{id, email}` | No way to know if the user is an operator or has verified their email. Fix (F0b-2) | F2, F6 |
| 5 | **Emails carry a raw token, not a link**, and say "POST it to \<base>/auth/verify". The reset email says the token lasts 24 hours but it lasts 30 minutes | Real users cannot verify or reset. Fix: links to `https://app.<domain>/verify-email?token=...` and `/reset/<token>` (new config `GP_APP_URL`), correct the 24-hour text | F2 |
| 6 | **OAuth callback returns JSON** `200 {ok}` instead of redirecting | The browser would land on a JSON page. Fix (F0b-5): redirect into the app, errors to `/signin?error=<allow-listed code>` | F2 (OAuth only) |
| 7 | **No customer alerts route** and no operator alerts route. Alerts are keyed by hostname | The Alerts pages have no data. Fix (F0b-3, F0b-6), with customer-safe detail text | F5, F6 |
| 8 | **No route to read the WAF change trail** (`domain_waf_changes` is written but never exposed); no origin change trail | The activity page has no data. Fix (F0b-4) | F4 |
| 9 | **No traffic-target instructions.** The API returns only the TXT ownership record. It does not say where the customer should point DNS (CNAME or A) for traffic | Wizard step 5 cannot show real values. The backend needs a configured edge hostname or IP list and a field for it | F3 |
| 10 | **No "live on the edge" status.** Nodes report an applied snapshot generation, but no domain-level field exists. No certificate or first-request data either | UI can say "verified" and "settings saved", never "live". Proposal in F0b-0c | F3 polish |
| 11 | Does sign-in require a verified email? The extract does not say | Decides what an unverified user sees | F2 |
| 12 | `excluded_rule_ids` has no maximum length | A huge list could bloat the signed config (256 KiB cap). Add a cap of 100 | F4 |
| 13 | Origin saves share the domain-add rate cap (20 per 15 min) | Repeated saves can show "rate limit exceeded for domains:add". Backend should use its own cap | F3 |
| 14 | Lockout gives no time left and no `Retry-After` | Generic wording only | Later |
| 15 | Password rule is 8 to 128 characters | The earlier PRD wanted 12. Decide: keep 8 and add a common-password check, or raise the minimum | F2 |
| 16 | `disabled` status is never set by any code | Show a neutral label | Later |
| 17 | Nameserver mode and DNS record routes exist, but no Gatepost DNS server does | Hidden in v1 | Later |
| 18 | Global snapshot cap is about 965 domains; the API refuses new domains near it (422) | UI shows a capacity message. Backend needs compression or sharding before real onboarding | Public launch |

**Items only you can do**

| # | Item | Needed by |
| --- | --- | --- |
| 1 | A public HTTPS address for the API (production, and a separate staging) with TLS, restarts and health checks | Before staging |
| 2 | A real domain for `app.`, `api.` and the marketing site, with DNS control (cookies, email SPF and DKIM, OAuth redirect URIs) | Before F2 in production |
| 3 | Google and GitHub OAuth apps with redirect URIs `https://app.<domain>/backend/auth/oauth/<provider>/callback`; set `GOOGLE_CLIENT_ID` and the others on the API | Before F2 OAuth |
| 4 | Zoho SMTP details for `GP_MAIL_*` (the outbox driver refuses to run in production) | Before F2 in production |
| 5 | Neon connection strings (`DATABASE_URL` pooled, `DATABASE_URL_DIRECT` for migrations) | Before staging |
| 6 | Logo and wordmark, or a decision to start with plain type | F1 |
| 7 | Terms and privacy text, reviewed by a lawyer | Before public launch |
| 8 | A Vercel paid plan and an error-reporting account | F1 and F8 |

**Deliberately not in this release:** billing, DNS hosting, caching, bot detection, GeoIP, analytics, team members and API keys. The earlier [Frontend and UI PRD](https://claude.ai/artifact/AXnQGiMr5VhbhiDFp5U9u2) covers them for later phases.

**Using this document.** The frontend repo keeps a copy as `docs/prd.md`. The coding agent's first prompt includes the essential parts, so exporting is optional.
