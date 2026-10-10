=====================================================================================================
WOLFEYE - DEVELOPER CHANGE SPECIFICATION
Inline Threat Aggregator and Blocking System
Prepared: October 2026
=====================================================================================================

HOW TO READ THIS FILE
---------------------
- Part 1 explains the goal and the decisions already made by the product owner.
- Part 2 lists corrections to the EXISTING code (do these first, they are small).
- Part 3 lists NEW components to build.
- Part 4 lists tests, acceptance criteria and delivery phases.
- Items marked [CONFIRM] were not visible to the author (only README.md, architecture.md and
  project-architecture-methodology.md were available, not the source code). Check them in the repo.
- Items marked [ASSUMPTION] are defaults chosen by the author. Change them if needed, but note the
  change in the PR.

=====================================================================================================
PART 1 - GOAL AND DECISIONS
=====================================================================================================

1.1 GOAL
WolfEye today collects threat feeds, enriches indicators, scores them and shows alerts. The new goal is
to turn it into an INLINE system that also enforces decisions:

  - It sits between the application layer and the transport layer, so it sees client IPs, URLs and
    other request details.
  - It checks what it sees against threat intelligence (VirusTotal, AbuseIPDB, Shodan, local IOC
    database, MISP/OpenCTI where enabled) and against a hybrid ML model.
  - Suspicious items go to a human expert, who decides to block or allow.
  - DoS/DDoS-style behaviour (repeated requests from one IP) is blocked automatically, without waiting
    for a human.
  - It must work on any OS and be usable for personal use and for companies protecting their own
    applications.

1.2 DECISIONS ALREADY MADE BY THE PRODUCT OWNER
  D1. Deployment modes: ALL THREE must be supported:
        Mode 1 - Reverse-proxy gateway (protects apps placed behind it)
        Mode 2 - In-app middleware (first target: Python/Flask)
        Mode 3 - Local host mode for personal use on one machine (local proxy + packet capture)
  D2. Suspicious but NOT DoS/DDoS: let the request through, alert the expert, and block only AFTER the
      expert decides. (No automatic blocking and no holding of the request for these cases.)
  D3. DoS/DDoS-style repeated requests from one IP: block automatically (rule-based, no human wait).
  D4. ML approach: add a PACKET-CAPTURE module that computes the full CICIDS2017 flow features, so the
      existing CNN-LSTM (52 features) can be used on live traffic.

1.3 CONSEQUENCES THE DEVELOPER MUST KEEP IN MIND
  C1. The CNN-LSTM was trained on lab traffic (CICIDS2017). Live traffic can look different (domain
      shift). The model must first run in SHADOW MODE (score and log only) and be evaluated on locally
      captured benign traffic before its output is shown to experts as a high-priority signal.
  C2. ML output never blocks anything by itself (decision D2). Only the DoS/rate rules block
      automatically (decision D3). Experts block everything else.
  C3. Encrypted traffic: unless the component terminates TLS itself (possible in Mode 1 and Mode 2),
      only IP addresses, ports, SNI and flow statistics are visible. URLs and payloads are not.
  C4. Volumetric DDoS that saturates the network link cannot be stopped by software on the same link.
      The product handles application-level floods and repeated-request abuse. Document this limit.
  C5. Packet capture needs elevated rights (root/CAP_NET_RAW, Administrator + Npcap on Windows,
      BPF access on macOS). The installer and docs must say so.

=====================================================================================================
PART 2 - CORRECTIONS TO THE EXISTING CODE (DO FIRST)
=====================================================================================================

2.1  SCORER OWNERSHIP
     Problem: architecture.md says alerts come from Isolation Forest with a heuristic fallback, while
     project-architecture-methodology.md says the live score is the heuristic formula and Isolation
     Forest is a batch path.
     Change: choose ONE and make code, docs and tests agree. Recommended:
       - risk_score    = heuristic formula (existing: source 0.55 + VT + AbuseIPDB + ports + reputation)
       - anomaly_score = Isolation Forest output
       - Alert severity is banded from risk_score; anomaly_score is shown next to it as a second signal.

2.2  SEPARATE SCORE COLUMNS
     Problem: heuristic scores and Isolation Forest scores share one column (anomaly_score) and one set
     of severity bands, but their distributions differ.
     Change: add columns to the IOC table (see 3.9): risk_score, anomaly_score, score_method.
     Migrate existing rows: copy old anomaly_score into risk_score where score_method was heuristic. [CONFIRM]

2.3  ISOLATION FOREST NORMALISATION
     Problem: min-max scaling is done per batch, so the same IOC gets different scores in different
     batches.
     Change: compute and save raw_min / raw_max (or training percentiles) at TRAINING time inside the
     model artefact (model.joblib or a sidecar JSON) and reuse them at scoring time. Clamp to [0,1].

2.4  ISOLATION FOREST FEATURE VECTOR
     Problem: the two docs list different vectors, and hash-based numbers for source/type have no
     meaning for a tree model.
     Change: one documented vector, with one-hot or frequency encoding for source and type
     (or remove them). Keep feature order in one constant used by both training and prediction.

2.5  ALERT FLOODING CHECK
     Problem: s_source = 0.55 and the Low band starts at 0.60, so one VirusTotal detection (1/20 = 0.05)
     from a trusted-malicious feed already creates an alert.
     Change: plot the real score distribution on the production-like data, then tune thresholds and make
     them configurable (ALERT_MIN_SCORE, severity band edges). Document that weights are expert-assigned.

2.6  CNN-LSTM WORDING AND EVALUATION
     - Input (52,1) makes the LSTM step across feature positions, not across time. Call it
       "sequential dependencies across flow features" in code comments and docs. (If windowed flows are
       added later, then "temporal" can be used.)
     - Deduplicate rows BEFORE the train/test split and keep the split stratified.
     - Report per-class precision, recall, F1, macro-F1 and a confusion matrix, not only accuracy.
     - Save the exact ordered list of the 52 feature names with the model (needed by section 3.5).

2.7  HOUSEKEEPING
     - Remove "Member B / Member C" from architecture.md.
     - Add scheduler, integrations (MISP/OpenCTI) and Streamlit to the architecture diagram.
     - State the Keras backend used (Keras 3 on PyTorch) and one supported Python range.
     - [CONFIRM] whether playbook actions (investigate/watchlist) run automatically or only when an admin
       triggers them; document the real behaviour.

=====================================================================================================
PART 3 - NEW COMPONENTS
=====================================================================================================

3.1  TARGET ARCHITECTURE (TEXT DIAGRAM)
-----------------------------------------------------------------------------------------------------
  CLIENT / ATTACKER
        |
        v
  +------------------------------ DATA PLANE (new) ---------------------------------+
  |  Mode 1: reverse-proxy gateway   Mode 2: in-app middleware   Mode 3: host mode   |
  |  - extract request details       - extract request details   - local proxy       |
  |  - fast checks (local only)      - fast checks (local only)   - packet capture    |
  |  - DoS/rate engine -> auto-block - DoS/rate engine            - flow features    |
  |  - send events (batched, async)  - send events (batched)      - OS firewall adapter|
  +----------------------------------------+-----------------------------------------+
                                           |  events (HTTPS, token auth)
                                           v
  +------------------------------ CONTROL PLANE (existing Flask app, extended) -------+
  |  Event intake -> enrichment (VT/AbuseIPDB/Shodan/MISP/OpenCTI) -> scoring        |
  |  (heuristic + Isolation Forest + CNN-LSTM) -> alert + review item -> expert UI   |
  |  Expert decision -> blocklist/allowlist -> pushed/polled back to the data plane  |
  |  Audit log, RBAC, dashboard, PDF reports (existing)                              |
  +----------------------------------------------------------------------------------+

  Rule: the data plane NEVER calls external threat APIs in the request path. It only uses local data
  (blocklist, allowlist, rate counters, cached IOC lookups). All API calls and ML run in the control
  plane, asynchronously.

3.2  REPOSITORY LAYOUT (PROPOSED)
-----------------------------------------------------------------------------------------------------
  wolfeye/
    app/                      (existing Flask control plane, extended)
    gateway/                  NEW  - Mode 1 reverse-proxy gateway
    middleware/               NEW  - Mode 2 in-app middleware (wolfeye_middleware package)
    hostagent/                NEW  - Mode 3 local proxy + firewall adapters
    capture/                  NEW  - packet capture + CICIDS2017 flow-feature extraction (shared by
                                     gateway option, host mode and a standalone sensor)
    core/                     NEW  - shared library used by all data-plane parts: rate engine, list
                                     cache, event schema, control-plane client, config
    ml/                       (existing models) + feature-name list + training scripts
    tests/ , docs/ , Dockerfile(s), docker-compose.yml
  [ASSUMPTION] Python 3.11+ for all new parts, so code in core/ is shared. Gateway logic must stay
  behind interfaces so it can be rewritten in Go/Rust later if performance requires it.

3.3  SHARED CORE LIBRARY (core/)
-----------------------------------------------------------------------------------------------------
  a) Event schema (JSON). Fields:
       event_id, ts_utc, node_id, mode (gateway|middleware|host), direction (inbound|outbound),
       src_ip, dst_ip, src_port, dst_port, protocol, method, host, path, query_redacted,
       user_agent, status_code, bytes_in, bytes_out, flow_id, flow_features (optional, 52 values),
       decision (allowed|auto_blocked|dry_run_blocked), decision_reason
  b) Redaction rules (default ON): drop Authorization, Cookie, Set-Cookie headers; never store request
     or response bodies; strip query values for keys named like token, key, password, secret.
  c) Control-plane client: batches events (default every 2 s or 200 events), retries with backoff,
     buffers to disk if the control plane is unreachable (bounded size), authenticates with a node
     token (header X-WolfEye-Node-Token).
  d) List cache: in-memory blocklist and allowlist with expiry times; refreshed by polling
     GET /api/enforcement/lists every ENFORCEMENT_POLL_SECONDS (default 5) or by push (SSE) if
     available. Supports exact IP, CIDR and (optionally) domain/URL-prefix entries.
  e) Rate engine (see 3.6).
  f) Config loader (environment variables, see 3.12).

3.4  DATA PLANE MODE 1 - REVERSE-PROXY GATEWAY (gateway/)
-----------------------------------------------------------------------------------------------------
  Purpose: companies put it in front of their web apps or APIs. Works on any OS (runs in Docker or
  as a plain Python service).
  Requirements:
   1. Listens on a configurable port, forwards to one or more upstream app URLs (UPSTREAM_URLS).
   2. Optional TLS termination (cert/key paths) so URLs and headers can be inspected. If not
      terminating TLS, it must be documented as metadata-only.
   3. Determines the real client IP: use the socket address by default; trust X-Forwarded-For only for
      addresses listed in TRUSTED_PROXIES (prevents header spoofing).
   4. For every request, in this order (all local, target added latency p95 < 5 ms [ASSUMPTION - measure]):
        a. allowlist hit  -> forward, skip other checks
        b. blocklist hit  -> reject (HTTP 403, or close the connection) and log
        c. rate engine    -> if limit exceeded, auto-block (3.6), reject, log
        d. otherwise      -> forward to upstream
   5. After forwarding, emit an event to the event queue (non-blocking; never delay the response).
   6. Fail-open by default: if the control plane or list refresh fails, keep using the last cached
      lists and keep forwarding. Option FAIL_MODE=open|closed applies only to "no cached lists yet".
   7. Suspicious (non-DoS) requests are NOT held or blocked (decision D2). They are forwarded and
      reported; blocking happens only when the expert's decision reaches the gateway through the list
      update.
   8. Health endpoints: /_wolfeye/health (gateway status, list version, last sync time).
   9. Dry-run mode (DRY_RUN=true): log what WOULD be blocked, but forward everything.
  10. Kill switch: a control-plane setting BLOCKING_ENABLED=false makes all nodes stop blocking within
      one poll interval.

3.5  PACKET CAPTURE AND CICIDS2017 FLOW FEATURES (capture/)   (decision D4)
-----------------------------------------------------------------------------------------------------
  Purpose: give the existing CNN-LSTM the same 52 flow features it was trained on, computed from live
  traffic.
  Requirements:
   1. Capture library: libpcap (Linux/macOS) and Npcap (Windows) through a cross-platform Python
      layer (scapy or dpkt/pcapy-ng) [ASSUMPTION - benchmark and pick]. Interface name and BPF filter
      configurable (CAPTURE_INTERFACE, CAPTURE_FILTER).
   2. Build bidirectional flows keyed by (src_ip, dst_ip, src_port, dst_port, protocol) with
      idle and active timeouts (defaults FLOW_IDLE_TIMEOUT=120 s, FLOW_ACTIVE_TIMEOUT=120 s,
      matching CICFlowMeter-style behaviour).
   3. Compute the exact 52 features, in the exact order, with the exact definitions used to produce
      cicids2017_cleaned.csv. [CONFIRM] The ordered feature list must be stored with the model
      (see 2.6) and loaded from there, not retyped.
      Reference implementations to study: CICFlowMeter (Java, Canadian Institute for Cybersecurity)
      and its Python ports.
   4. Parity test (mandatory): take pcap files from the CICIDS2017 distribution, run them through the
      new extractor, and compare the output with the published CSV rows for the same flows. Report
      per-feature mismatch rate and distribution drift. Fix definitions until differences are explained
      or documented. Without this test the model result on live traffic is not trustworthy.
   5. Output: for each finished flow, send flow_id + 52 features + src/dst info to the scoring
      service (see 3.7) through the event pipeline.
   6. Performance: capture must not run in the request path of the gateway. It runs as a separate
      process/thread. Document the maximum sustained packets/second tested.
   7. Privacy: capture reads headers and counters only. Do not store payload bytes.
   8. Permissions: document and check at start-up (clear error if not root/Administrator/Npcap missing).
   9. Capture can run (a) next to the gateway on the same server, (b) in host mode on a personal
      machine, or (c) as a standalone sensor on a mirror/SPAN port. Same code, different config.

3.6  RATE / DoS ENGINE (core/) - AUTOMATIC BLOCKING   (decision D3)
-----------------------------------------------------------------------------------------------------
  Rule-based, no ML. Runs inside every data-plane node (and per node, local state).
  Requirements:
   1. Sliding-window counters per source IP: requests per window, new connections per window, and
      (when capture is on) SYN/half-open counts per window.
   2. Default thresholds [ASSUMPTION - tune with load tests]:
        RATE_LIMIT_REQUESTS=100 per RATE_WINDOW_SECONDS=10 per IP
        RATE_LIMIT_CONNECTIONS=50 per 10 s per IP
   3. When exceeded: create a temporary block entry with an expiry (TTL) and escalate on repeat:
        1st offence 10 min -> 2nd 1 hour -> 3rd 24 hours (configurable list BLOCK_ESCALATION).
      Reset the offence count after a quiet period (default 7 days).
   4. Safety rules (must exist): never auto-block allowlisted IPs, loopback, private ranges that
      belong to the operator (configurable OWN_NETWORKS), health-check sources, or the control
      plane address. Handle shared IPs (company NAT, mobile carriers) by using a higher threshold
      for IPs that show many distinct user sessions [ASSUMPTION - optional in first release].
   5. Every automatic block creates: an event, an audit log entry (actor = "system:rate-engine",
      reason, counters), and an alert (severity at least Medium) so experts can review or unblock.
   6. Auto-blocks are sent to the control plane so that other nodes can share them
      (optional, SHARE_AUTO_BLOCKS=true).
   7. Expert can unblock at any time; the unblock must reach nodes within one poll interval.
   8. Document limit C4 (volumetric attacks need upstream protection such as CDN/ISP filtering).

3.7  CONTROL PLANE: EVENT INTAKE, ENRICHMENT, SCORING (app/ - extend existing)
-----------------------------------------------------------------------------------------------------
  1. New endpoint POST /api/events/batch (node token required, rate limited). Accepts up to
     EVENT_BATCH_MAX events (default 500). Validates schema, rejects oversize payloads.
     Keep POST /api/observations for the existing agent (backward compatible).
  2. Extract indicators from events (client IP, destination IP, host, URL) and look them up:
       a. Local IOC table first (existing, from public feeds + MISP/OpenCTI). Use an in-memory
          index or Bloom filter for speed. [ASSUMPTION]
       b. Enrichment for unknown indicators through the existing enrichment service
          (VirusTotal, AbuseIPDB, Shodan), asynchronously, with the existing 24 h cache and
          rate-limit handling (VirusTotal free tier is about 4 requests/minute: use a queue).
  3. Scoring per event/indicator (all asynchronous):
       - risk_score    : existing heuristic
       - anomaly_score : Isolation Forest on request-level features (see 3.8)
       - flow result   : CNN-LSTM class + confidence, only for events carrying flow_features
  4. Decision logic (documented in code and docs):
       - A DoS/rate-engine block from the data plane is already final (decision D3).
       - If risk_score >= ALERT_MIN_SCORE, OR a high-confidence malicious IOC matches, OR the
         CNN-LSTM predicts an attack class with confidence >= FLOW_ALERT_CONFIDENCE (default 0.90,
         only after shadow-mode validation C1): create an Alert and a Review Item.
       - Nothing in this step blocks automatically (decision D2).
       - Option AUTO_BLOCK_ON_CRITICAL_IOC_MATCH=false (default). [ASSUMPTION] Matching a known C2/
         malware IP is still sent to the expert by default; the owner may switch auto-block on.
  5. Notification: dashboard review queue + existing email notifier for High/Critical. Optional
     webhook (Slack/Teams) behind a config flag.
  6. ML mode switch: FLOW_MODEL_MODE=shadow|advisory. In shadow, predictions are stored and shown only
     on a diagnostics page; in advisory, they can create alerts. Default: shadow.

3.8  ISOLATION FOREST FOR REQUEST-LEVEL FEATURES
-----------------------------------------------------------------------------------------------------
  Add a second Isolation Forest model for gateway events (keep the existing IOC model unchanged).
  Candidate features per source IP over a window (all measurable at the gateway):
    request count, distinct paths, distinct user agents, error-status ratio (4xx/5xx), mean and
    max URL length, URL entropy, bytes in/out, request inter-arrival mean and variance, ratio of
    requests to sensitive routes (login/admin) [CONFIRM list of sensitive routes per deployment].
  Train on locally collected benign traffic (dry-run period), save with raw_min/raw_max (see 2.3).

3.9  DATABASE CHANGES (app/models/ - add migrations)
-----------------------------------------------------------------------------------------------------
  Use real migrations (Alembic) so SQLite (dev) and PostgreSQL (prod) stay in sync. [CONFIRM current
  migration approach]
  IOC (alter):          add risk_score FLOAT, score_method VARCHAR; keep anomaly_score for Isolation Forest.
  Node (new):           id, name, mode, token_hash, last_seen, version, created_at, active
  BlockEntry (new):     id, kind (ip|cidr|domain|url_prefix), value, reason, source (expert|rate_engine|
                        ioc_match), created_by, created_at, expires_at (nullable = permanent), active,
                        related_alert_id (nullable)
  AllowEntry (new):     id, kind, value, reason, created_by, created_at, expires_at
  ReviewItem (new):     id, alert_id (FK), subject (ip/url/flow), evidence_json (scores, IOC matches,
                        enrichment summary, recent events), status (open|blocked|cleared), decided_by,
                        decided_at, decision_note
  FlowRecord (new):     id, flow_id, node_id, src_ip, dst_ip, ports, protocol, features (JSON or
                        columns), cnn_lstm_class, cnn_lstm_confidence, created_at
  EventLog (new):       short-retention table (default 7 days, configurable EVENT_RETENTION_DAYS) for
                        flagged and sampled events only. Do NOT store every request in the main database;
                        keep aggregates for the dashboard and purge with a scheduled job.
  AuditLog (alter):     add actor_type (user|system|node) and node_id; keep append-only.
  Config (new):         key/value table for runtime settings (BLOCKING_ENABLED, thresholds).
  All new tables: indexes on (value, active, expires_at) for lists and on (created_at) for purging.

3.10 ENFORCEMENT API AND REVIEW WORKFLOW (app/routes/ - new blueprints)
-----------------------------------------------------------------------------------------------------
  New endpoints (names are proposals):
    GET    /api/enforcement/lists            nodes: active blocklist+allowlist with version number
                                             (supports If-None-Match / since=version)
    POST   /api/enforcement/blocks           analyst/admin: create block (value, kind, reason, ttl)
    DELETE /api/enforcement/blocks/<id>      analyst/admin: unblock
    POST   /api/enforcement/allows           analyst/admin: create allow entry
    DELETE /api/enforcement/allows/<id>
    GET    /api/review                       list review items (filters: status, severity, node)
    GET    /api/review/<id>                  evidence view
    POST   /api/review/<id>/block            expert decision: block (ttl or permanent) -> creates
                                             BlockEntry, audit entry, marks item blocked
    POST   /api/review/<id>/clear            expert decision: mark safe -> optional AllowEntry with
                                             expiry; stored as a labelled example for retraining
    POST   /api/events/batch                 nodes only (see 3.7)
    GET    /api/nodes ; POST /api/nodes ; POST /api/nodes/<id>/rotate-token     admin only
    GET    /api/system/enforcement-status    blocking enabled flag, list version, nodes last seen
  Auth/roles: add role "analyst" between readonly and admin:
    readonly: all GET except tokens/config   analyst: review decisions + block/allow/unblock
    admin: everything including nodes, tokens, config, kill switch.
  Rate limiting (flask-limiter) on all write endpoints; validation with explicit field checks
  (follow existing pattern).
  Workflow: alert created -> review item open -> expert opens evidence -> Block (with TTL) or Clear ->
  lists version increases -> nodes fetch within poll interval -> data plane enforces -> audit shows
  who/when/why.

3.11 DASHBOARD / UI (templates + JS)
-----------------------------------------------------------------------------------------------------
  - Review queue page: sortable table, severity filter, evidence panel (IOC matches, VirusTotal/
    AbuseIPDB summary, ML scores, last N events from that IP), buttons Block / Clear / Block with TTL.
  - Blocklist/allowlist management page with expiry, source (expert/rate_engine), and unblock action.
  - Nodes page: status, mode, last seen, list version, blocked-count, dry-run flag.
  - Live traffic widgets: requests/s, auto-blocks in last hour, top source IPs, flagged events.
  - ML diagnostics page: shadow-mode predictions vs expert decisions (precision of ML alerts so far).
  - Controls: global BLOCKING_ENABLED toggle (admin), dry-run indicator banner.
  - Keep existing pages (IOCs, alerts, map, PDF reports) and add blocks/review counts to the PDF.

3.12 CONFIGURATION (ENVIRONMENT VARIABLES, ADD TO .env.example)
-----------------------------------------------------------------------------------------------------
  CONTROL_PLANE_URL, NODE_TOKEN, NODE_NAME, NODE_MODE
  UPSTREAM_URLS, LISTEN_HOST, LISTEN_PORT, TLS_CERT_PATH, TLS_KEY_PATH
  TRUSTED_PROXIES, OWN_NETWORKS
  FAIL_MODE (open|closed), DRY_RUN, BLOCKING_ENABLED
  RATE_LIMIT_REQUESTS, RATE_LIMIT_CONNECTIONS, RATE_WINDOW_SECONDS, BLOCK_ESCALATION
  ENFORCEMENT_POLL_SECONDS, SHARE_AUTO_BLOCKS
  CAPTURE_ENABLED, CAPTURE_INTERFACE, CAPTURE_FILTER, FLOW_IDLE_TIMEOUT, FLOW_ACTIVE_TIMEOUT
  ALERT_MIN_SCORE, FLOW_MODEL_MODE, FLOW_ALERT_CONFIDENCE, AUTO_BLOCK_ON_CRITICAL_IOC_MATCH
  EVENT_BATCH_MAX, EVENT_RETENTION_DAYS
  Existing keys remain (SECRET_KEY, VIRUSTOTAL_API_KEY, SHODAN_API_KEY, ABUSEIPDB_API_KEY,
  DATABASE_URL, LOCAL_INGEST_TOKEN, SMTP settings, MISP/OpenCTI settings).

3.13 MODE 2 - IN-APP MIDDLEWARE (middleware/)
-----------------------------------------------------------------------------------------------------
  Purpose: developers embed protection directly in their app.
  Requirements:
   1. Package name wolfeye_middleware, installable with pip. First adapter: WSGI (works with Flask and
      Django) with an ASGI adapter next if time allows. Other languages (Node/Express, Java) are
      future work: keep the protocol (event schema, enforcement API) language-neutral and documented.
   2. Same sequence as the gateway (allowlist, blocklist, rate engine, forward, async event emit),
      using the shared core/ library. One-line setup:  app.wsgi_app = WolfEyeMiddleware(app.wsgi_app, config)
   3. Returns 403 (configurable body) for blocked IPs; never raises exceptions into the host app
      (fail-open on any internal error, and log the error).
   4. Adds no more than a small, measured overhead (benchmark and publish p95 numbers).
   5. Does not read or store request bodies. Redaction rules from 3.3(b) apply.

3.14 MODE 3 - LOCAL HOST MODE FOR PERSONAL USE (hostagent/)
-----------------------------------------------------------------------------------------------------
  Purpose: protect one personal computer (all apps), any major OS.
  Requirements:
   1. Local forward proxy on 127.0.0.1:<port> that proxy-aware apps and browsers can use
      (guide for setting the system proxy on Windows, macOS, Linux). It applies the same fast checks
      and rate engine. For HTTPS it sees host/SNI only unless the user installs and trusts a local
      CA certificate (opt-in, with clear warning). [ASSUMPTION - first release: no TLS interception
      by default]
   2. Packet capture (3.5) runs on the machine to observe ALL traffic (also from apps that ignore the
      proxy), computes flow features and sends them to the control plane (local or cloud).
   3. Direction = outbound for destinations: the destination IPs/domains are checked against the IOC
      database (malware C2, phishing domains). Alerts follow the same expert flow (D2). For a
      single-user install the user can be their own expert (role admin) or connect to a company
      control plane.
   4. Enforcement beyond the proxy uses a FIREWALL ADAPTER interface with one implementation per OS:
        Linux   : nftables (iptables fallback)
        Windows : Windows Filtering Platform / netsh advfirewall
        macOS   : pf
      The adapter only adds/removes rules for entries in the blocklist, tagged with a WolfEye name so
      they can be removed cleanly. Needs admin/root; must clean up rules on uninstall and on crash
      recovery. Build Linux first; Windows and macOS adapters follow behind the same interface.
   5. Runs as a background service (systemd unit, Windows service, macOS launchd) with auto-restart.
      Provide a simple tray/CLI status command. Package: pip entry point plus installers/PyInstaller
      builds. [ASSUMPTION]
   6. Same safety rules as 3.6(4): never block the local gateway, DNS resolvers, default gateway,
      loopback or the control-plane address (otherwise the user can lock themselves out).

3.15 SECURITY AND PRIVACY REQUIREMENTS (ALL NEW PARTS)
-----------------------------------------------------------------------------------------------------
   - Node-to-control-plane: HTTPS only, per-node tokens stored hashed, rotation endpoint, optional mTLS.
   - No bodies, no cookies, no authorization headers stored. Redaction is on by default and tested.
   - Event retention limit and purge job (EVENT_RETENTION_DAYS). Document what is stored.
   - TLS interception (if enabled) is opt-in, documented, and requires the owner's consent notice in
     docs and UI.
   - All new endpoints: auth + role checks, rate limiting, input validation, audit entries for any
     state change (block, unblock, allow, config change, token rotation).
   - Secrets only from environment/.env; none in code or logs. Scrub tokens from log output.
   - Dependency pinning and a basic vulnerability scan (pip-audit) in CI.

=====================================================================================================
PART 4 - TESTING, ACCEPTANCE AND DELIVERY
=====================================================================================================

4.1  TEST REQUIREMENTS
  Unit tests:
    - severity band boundaries (0.59, 0.60, 0.69, 0.70, 0.79, 0.80, 0.89, 0.90, 1.00)
    - heuristic score formula (each term and the min(1, ...) cap)
    - Isolation Forest normalisation uses saved min/max (same input -> same score across batches)
    - rate engine: window edges, escalation 10 min -> 1 h -> 24 h, expiry, allowlist/own-network bypass
    - client IP extraction with and without TRUSTED_PROXIES (spoofed X-Forwarded-For is ignored)
    - redaction rules (Authorization, Cookie, token-like query values removed)
    - event batch validation (oversize, bad schema, bad token)
    - role checks for readonly / analyst / admin on each new endpoint
  Integration tests:
    - end-to-end: request -> gateway -> event -> control plane -> alert -> review item -> expert block
      -> list update -> next request from that IP rejected
    - control plane down: gateway keeps serving using cached lists; events buffered and delivered later
    - dry-run: nothing blocked, "would block" logged
    - kill switch: BLOCKING_ENABLED=false stops blocking on all nodes within one poll interval
  Flow-feature tests (capture/):
    - parity test against CICIDS2017 pcaps (see 3.5.4) with a written report
    - replay of known attack pcaps (DoS, port scan, brute force) producing the expected classes in
      shadow mode, with precision/recall noted
  Load and abuse tests:
    - load test (e.g. Locust/k6/wrk) at stated request rates: report added latency p50/p95/p99
    - simulated single-IP flood: IP is auto-blocked inside the configured window; legitimate IPs
      are unaffected
    - false-block test: normal browsing and API clients at realistic speeds are never blocked
    - shared-IP scenario test
  Cross-platform matrix: run the gateway (Docker/Linux), middleware (Linux, Windows, macOS) and host
  mode (Linux, Windows, macOS) smoke tests; record results per OS.
  Security tests: token misuse, role escalation attempts, injection attempts on new endpoints, log scan
  for leaked secrets.

4.2  ACCEPTANCE CRITERIA (DEFINITION OF DONE)
    A1. A single-IP flood against the gateway is blocked automatically within RATE_WINDOW_SECONDS,
        with an audit entry and an alert, and normal clients are unaffected.
    A2. A suspicious (non-DoS) request is forwarded, an alert and review item appear in the dashboard,
        and the IP is blocked only after an analyst clicks Block; the gateway enforces it within
        one poll interval.
    A3. Unblocking by an analyst restores access within one poll interval.
    A4. The gateway keeps working if the control plane is stopped (fail-open with cached lists).
    A5. No call to VirusTotal/AbuseIPDB/Shodan happens in the request path (verified by test).
    A6. Packet capture produces the 52 features in the model's feature order; the parity report is
        attached to the PR; CNN-LSTM runs in shadow mode on live capture.
    A7. All three modes start and pass their smoke tests on their target OS list.
    A8. Redaction verified: no cookies, auth headers or bodies in any stored event.
    A9. Existing features (feeds, enrichment, MISP/OpenCTI, dashboard, PDF, Streamlit) still pass
        existing tests.
    A10. Documentation updated (see 4.4).

4.3  DELIVERY PHASES (SUGGESTED ORDER, EACH PHASE MERGED BEHIND TESTS)
    Phase 0 - Corrections (Part 2).
    Phase 1 - Control plane: migrations, node tokens, event intake, enforcement API, review queue UI,
              analyst role, audit changes, config table, kill switch.
    Phase 2 - core/ library + Mode 1 gateway + rate engine + dry-run + list sync. (First demo: A1-A5.)
    Phase 3 - Mode 2 middleware (WSGI) reusing core/.
    Phase 4 - capture/ module, flow features, parity test, shadow-mode CNN-LSTM, ML diagnostics page.
    Phase 5 - Mode 3 host mode: local proxy, service wrappers, Linux firewall adapter, then Windows
              and macOS adapters.
    Phase 6 - Hardening: load tests, security tests, packaging (Docker images, pip packages,
              installers), documentation, demo script.
  Phase 4 and Phase 5 can start in parallel after Phase 2 if two developers are available.

4.4  DOCUMENTATION THAT MUST BE UPDATED WITH THE CODE
    - README.md and architecture.md: new architecture, three modes, flows, endpoints, schema.
    - New docs: deployment guide per mode, configuration reference, packet-capture permissions and
      install steps per OS, expert runbook (how to review/block/clear), security and privacy notes.
    - Methodology/mathematical-model doc: describe risk_score, anomaly_score, flow model, rate rules,
      escalation table, thresholds and how they were chosen.
    - Known limits: C1 (domain shift), C3 (encryption), C4 (volumetric DDoS), shared-IP caveat.
    - Synopsis, proposal, requirements, test plan and presentation to be aligned with the final
      behaviour (owner will update separately).

4.5  OPEN QUESTIONS FOR THE DEVELOPER TO ANSWER IN THE FIRST PR OR DESIGN NOTE
    Q1. Gateway implementation: Python asyncio (aiohttp/Starlette + httpx) first, or Go/Rust? Provide a
        quick benchmark to justify the choice.
    Q2. Which capture library meets the packets/second target on all three OSes (scapy vs dpkt/pcapy-ng
        vs a native helper)?
    Q3. Can all 52 features be reproduced exactly? List any that cannot and propose an action
        (retrain on the reproducible subset, or approximate and document).
    Q4. How are shared auto-blocks propagated safely (risk of one noisy node blocking a real user
        across all nodes)?
    Q5. Where are request-level features computed (data plane vs control plane) to keep the fast path
        light?
    Q6. TLS interception in host mode: leave out of v1, or include as opt-in?
    Q7. Retention and sampling policy for EventLog under heavy traffic.

=====================================================================================================
PART 5 - UI VISUAL STYLE AND PROFESSIONAL POLISH
=====================================================================================================

1. VISUAL STYLE & VIBE:
- Base the aesthetic on Tactical Editorial Design mixed with Premium Matte Skeuomorphism. It should look like an authoritative, high-density military or intelligence briefing document reimagined for software.
- Reference the precise, hyper-dense layout and spacing ethos of brands like Linear (for micro-details), Leica (for technical precision), and the NYT/Rest of World editorial layouts (for high-contrast data density).

2. COLOR PALETTE:
- Primary Background: Deep Matte Obsidian Charcoal (#0D0D0E) - absolute flat matte with zero blue or purple tint.
- Accents & Brand Colors: Striking Wolf Grey (#E4E4E7), Warning Amber/Ochre (#D97706) for critical indicators, and Tactical Muted Olive (#3F6212) for secure states. Used with extreme restraint (max 5% screen real estate).
- Text Hierarchy: Pitch white (#FFFFFF) for headers, crisp off-white (#E4E4E7) for body data, and muted technical gray (#71717A) for timestamps and metadata. No glows or text-shadows.

3. TYPOGRAPHY & SPACING:
- Typography: Use a sharp, high-end Monospace or technical Geometric Sans-Serif font combination (e.g., Geist Mono for metrics/logs and Geist Sans or Inter for functional text).
- Grid & Spacing: Rigid, high-density 8px grid system. Very compact but intentional padding, maximum data layout efficiency, and razor-thin, crisp 1px borders using #27272A to divide sections instead of drop shadows.

4. CONTENT & COMPONENT STRUCTURE:
- Do NOT use lorem ipsum. Use real, contextual cybersecurity data for these 3 specific areas:
  1. "Active Attack Vectors": A high-density feed showing "CVE-2026-3821 Exploitation Attempt", "IP: 185.220.101.5 (Tor Exit Node)", and "Target: Auth Gateway".
  2. "Aggregated Threat Feed": A tabular list featuring columns for [Timestamp, Threat Actor, Confidence Score %, Indicator of Compromise].
  3. "Network Anomalies Chart": A flat, step-line chart (no smooth curves, no glowing fills underneath) showing raw data packet spikes.
- Layout: An asymmetric layout dominated by a large, raw tabular central data frame, flanked by a narrow, hyper-functional technical metadata column on the right side.

5. INTERACTION & POLISH:
- Keep the UI flat, crisp, and snappy. Elements should look recessed into the interface using subtle 1px inset borders rather than floating over it.
- Use crisp, pixel-perfect, un-rounded geometric icons (like severe 90-degree angles).

=====================================================================================================
END OF SPECIFICATION
=====================================================================================================



