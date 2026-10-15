# Security Policy

**Legal Disclaimer.** TornadoC2 is a dual-use post-exploitation
framework intended for authorized security testing, red-team
operations, and research on systems you explicitly own or have
written permission to test. Its features can also be misused, and
the project cannot determine the operator's intent.

Use TornadoC2 only on systems you own or have explicit authorization
to test. You are responsible for your actions and for following all
applicable laws. The maintainers do not support or authorize illegal
or unethical use.

---

## Supported Versions

This project does not use version numbers or release tags. All
updates are pushed directly as commits to the `main` branch.

- The **latest commit on `main`** is always the supported version
  for security fixes.
- If you are pinned to a specific older commit, please update to
  the latest commit to receive patches.
- A security fix may be backported on a case-by-case basis for
  engagements that cannot move forward. Ask before assuming a
  backport will exist.

---

## Reporting a Vulnerability

In a post-exploitation framework, a "security vulnerability" means
a flaw in the **handler**, the **agent**, or the **team server**
that compromises one of the following:

- The integrity of the **operator host** or the **team server**.
- The confidentiality of the **wire traffic** between the agent and
  the handler.
- The **authentication** that gates a task, a result, a check-in,
  an operator request, or a pivot handshake.
- The **sandbox** that confines a WASM extension, a BOF, or a
  redirected child session.
- The **audit chain** that records operator actions.
- The **build pipeline** that produces an agent, when the flaw
  lets a hostile operator produce a binary different from the one
  the build config described.

If a defender can use your report to forge a task, decrypt a
captured envelope, impersonate a beacon, escalate a remote
operator's privileges, break the audit chain without detection,
escape the extension sandbox, or cause the handler to write a file
outside its tree, that is a security vulnerability. Report it
privately.

### Security-critical areas

The following are the categories the project treats as
security-critical. This is the list the
[Contributing Guide](CONTRIBUTING.md) references.

#### Cryptographic flaws

- **Signature verification bypass.** A task, result, or check-in
  identity signature that verifies when it should not. Includes
  canonicalisation mismatches in the task JSON, timestamp window
  bypass, and TOFU-pinning weaknesses.
- **ECDH key derivation flaws.** A wire-encryption key that is
  predictable, reused across sessions, or derivable from the
  public wire material alone.
- **AES-GCM envelope flaws.** Nonce reuse, missing additional
  authenticated data, a padding oracle, or a length leak in the
  response padding bucket.
- **Cookie forgery.** A session cookie that can be minted without
  the handler's cookie signing key, or a cookie whose HMAC can be
  computed from public material.
- **Cookie-name confusion.** A profile-declared `cookie_name` that
  causes the listener and a transport to read different cookie
  names. The HTTP listener's `_session_id` and the WebSocket
  dispatcher's `cname` variable both read `self._cookie_name`; a
  change that lets one read a different name than the other is a
  bug. The `cookie_name` character class check
  (`[A-Za-z0-9._-]`) is the reference; a value that reaches the
  wire without it is a bug.
- **mTLS and server-cert pin bypass.** A client certificate that
  authenticates when it should not, or a `server_cert_sha256` pin
  that is silently skipped when the peer certificate does not
  match.
- **Operator-password flaws.** An HMAC that can be forged without
  the password, a nonce that can be replayed within the ±300 s
  window, a salt that is not rotated on password change, or a
  scrypt parameter set that is weaker than documented.
- **Pivot handshake flaws.** A parent that can impersonate another
  parent to a child, a child that can impersonate another child to
  a parent, a sequence number that can be replayed or skipped, or
  an AEAD frame that can be edited in flight without breaking the
  tag.
- **Pivot keypair scope.** A pivot key that is embedded in the
  wrong half of a build — the private half in a child, the public
  half in a parent. The builder picks the correct half based on
  the build's role; a report that a build embeds the wrong half
  is a bug.
- **Staged-payload signature bypass.** A payload served from
  `/stage/<name>` that the stager executes without verifying the
  `X-Payload-Sig` header against the embedded handler public key.
  A build that produces a stager without an embedded
  `ServerPubKeyPem` — and therefore runs without signature
  verification — is documented and warned about at build time,
  but a report that the fallback silently accepts an unsigned
  payload against an operator's expectation is in scope.

#### Target-to-operator attacks

A compromised or malicious target manipulating its output to
attack the operator.

- **Terminal escape injection.** Task output, chat, notes, aliases,
  loot metadata, BOF names, C2 profile descriptions, or any other
  target-supplied string that is rendered on the operator's
  terminal without sanitization and that contains CSI / OSC / C0
  / C1 sequences. The chat sanitizer is the reference; every
  terminal-rendering path should match it.
- **Memory exhaustion.** A response body that bypasses the
  response size cap, a chat file that bypasses the per-file cap,
  or a session-log entry that bypasses the length cap.
- **Parser crashes.** A JSON body, a COFF header, a WASM module
  header, or a pivot handshake frame that causes a Python or Go
  parser to crash rather than refuse.
- **Path traversal via target metadata.** A target-reported
  hostname, username, or path that resolves outside `logs/` when
  the session directory is created. Every path the handler builds
  from target-supplied data is in scope.
- **Client-side filename traversal.** A loot or chat display name
  that causes the client to write outside the operator's current
  working directory on `loot get` or `/get`. The `/` and `\`
  replacement is the reference; a value that reaches the
  filesystem without it is a bug.

#### Secret exposure

- **Credential leakage to logs.** A password, an NT hash, a
  Kerberos key, a bearer token, a certificate private key, or a
  session cookie written to `logs/`, to `logs/audit/`, or to any
  mirror file, either in cleartext or in a reversible encoding.
  The credential vault's deliberate exclusion of the value from
  the audit chain is the reference.
- **Credential leakage to subprocess argv.** A `creds validate`
  invocation that passes the credential to a child process in a
  form visible to `ps aux`. The vault's design uses stdin and
  temporary files for this reason; a change that regresses that
  is a security bug.
- **Key material in memory dumps.** An agent or handler that
  leaves the agent signing key, the server ECDH key, the pivot
  private key, or the mTLS client key in a state that survives a
  controlled process exit. This is a best-effort category; report
  it if you have a specific reproduction, not as a general
  observation.
- **Linker-flag leakage.** A build config whose secret values —
  WireGuard private key, agent private key, mTLS client key —
  reach the agent's binary or the build output in a form the
  operator did not intend. The `stage_key_hex` written to
  `payloads/stage_keys.json` is the reference for a value that
  is documented as stored in a `0600` file and no further.

#### Privilege escalation

- **Remote operator privilege escalation.** A `viewer`,
  `operator`, or `guardian` credential that reaches a capability
  it does not hold. Includes capability-check bypass on a new
  endpoint, a capability that is enforced only on the client and
  not at `_with_cap`, and a capability that is advertised to a
  role that should not have it.
- **Admin-protection bypass.** A remote caller that creates,
  removes, demotes, or resets the password of an admin account.
  The `operator.*.admin` capabilities are `LOCAL_ONLY` by design;
  a remote path that reaches them is a bug.
- **Guardian-scope bypass.** A `guardian` credential that reaches
  a beacon, a credential, a loot blob, an extension, or another
  operator's config. The role exists to hold the dead-man's switch
  and nothing else.
- **Dead-man's switch control bypass.** A non-guardian credential
  that arms, resets, disables, halts, or changes the shred mode of
  the switch. The `crypto` shred mode's `confirm: true` requirement
  is a specific case — a request that reaches the LUKS-erase path
  without the confirmation flag is a bug.
- **Session-TTL bypass.** A request that is honoured after
  `SESSION_TTL_SECONDS` from the operator's first request in the
  current process.

#### Audit chain and integrity

- **Audit chain tampering.** Any operator action that writes an
  entry without being recorded, that records a different action
  than the one performed, or that causes the chain to verify when
  it should not.
- **Unlogged mutation.** A new state-changing endpoint that does
  not write an audit entry. The Contributing Guide names the
  action-name vocabulary; a mutation with no audit entry is a
  regression. The documented exceptions — `/api/v1/beacons` (the
  beacon listing) and the chat presence heartbeat — are the only
  two classes of request the chain does not record.
- **Checkpoint forgery.** An HMAC over the chain tail that can be
  recomputed without the checkpoint key.
- **`X-Audit-Id` header spoofing.** A response whose `X-Audit-Id`
  header or `audit_id` body field names an entry that does not
  correspond to the action performed. The ID is written by the
  same code path that writes the chain entry; a report that the
  two disagree is in scope.

#### Sandbox and parser boundaries

- **WASM extension sandbox escape.** A module that reaches a
  syscall, a file, a socket, or a memory region outside the four
  host functions and the 16 MiB memory ceiling. Includes a module
  that survives `unload`, one that persists state across reloads,
  or one that reaches another module's memory.
- **Extension loading from an unintended location.** An
  `extension load` that resolves a path outside the operator's
  local store, or that substitutes a different module for the one
  the operator named. The reserved-name check — a module whose
  name collides with a native verb — is the reference.
- **BOF registry substitution.** A registered BOF whose stored
  bytes change between registration and execution, or a name
  collision that lets one operator's BOF run under another's name.
  The `bofs` name regex and the COFF machine check are the
  reference.
- **Stager payload substitution.** A `/stage/<name>` response
  whose bytes are changed in transit and whose advertised SHA-256
  is rewritten to match. The `X-Payload-Sig` header is the
  defence; a report should demonstrate how it can be bypassed.

#### Server-side request and input handling

- **Build-config path injection.** A remote build config whose
  path fields resolve outside `mtls_certs/`, `tls_certs/`, and
  `profiles/c2/`. The whitelist is enforced on the server, not on
  the client; a path that reaches the compiler outside the
  whitelist is a bug. This includes `pivot_key_path`, which is
  covered by the `mtls_certs/` entry, and every `mtls.dir` /
  `mtls.cert` / `mtls.key` / `mtls.ca` override.
- **Build-time flag injection.** A config field whose value
  becomes a `-ldflags` argument without validation, allowing a
  build to set an arbitrary `-X` value or add a linker flag. The
  `dns_label` block is emitted as four dedicated `-X` flags and
  each value is validated by the transport constructors on the
  agent side; a report that a crafted value reaches the linker
  without validation is in scope.
- **Webhook URL SSRF.** A webhook whose URL resolves to a
  loopback, link-local, or cloud-metadata address. The dispatcher
  is fire-and-forget; a webhook pointing at `169.254.169.254`
  should be refused at registration, not on first fire.
- **DoH resolver URL SSRF.** A `--doh-resolver` value that
  points at a non-HTTPS URL, a loopback address, or a path that
  is not a DoH endpoint. The builder refuses a non-`https://`
  URL; a resolver URL that reaches a private service through a
  Worker or redirector is out of the builder's reach and is
  worth reporting if it can be demonstrated to bypass the
  check.
- **BOF name traversal.** A name that passes the registry's name
  regex but still resolves outside `bofs/`. The regex is the
  reference; a name that reaches the filesystem and escapes the
  directory is a bug.
- **C2 profile shaping-block validation bypass.** A profile whose
  `shaping` block passes the agent's `ValidateShapingSpec`
  round-trip but produces responses the agent cannot parse at
  runtime. The build-time validation is the defence; a report
  should demonstrate a specific profile that defeats it.
- **Profile-declared header injection.** A profile-declared
  `response_headers` entry or a shaping template whose rendered
  value carries `\r`, `\n`, or `\0`. The listener validates
  names and values against those bytes at load time; a value
  that reaches the HTTP response without passing the check is
  in scope. `response_headers` are merged after the
  framework-set headers (`Content-Type`, `Set-Cookie`, the
  `X-Beacon-*` scheduling headers); a report that a profile
  overrides one of the framework's own headers is in scope.
- **Encoding mismatch confusion.** A shape whose declared
  `encoding` the agent does not recognise falls back to `base64`
  silently on both sides. A report that a specific encoding value
  causes the listener and the agent to disagree — one side
  falling back, the other not — is in scope.
- **Placement mismatch on a transport that does not support it.**
  A profile that declares `placement: header` and a transport
  that cannot carry headers (WebSocket). The listener sets
  `TORNADO_WS` in the request environ and `_apply_placement`
  leaves the payload in the body; a report that the payload
  reaches the WebSocket frame in a location the agent does not
  read is in scope. QUIC honours placement — the QUIC listener
  returns the Flask response verbatim.
- **`dns_label` verb collision or range bypass.** A profile whose
  `dns_label` block declares a chunk size outside 1–63 or two
  verbs with the same character. The agent's transport
  constructors and the listener's `__init__` both refuse the
  collision — a collision resets all three verbs to `b/t/r` at
  once, on both sides — and clamp the size to 63. A value that
  reaches the wire without one of those checks firing is in
  scope.
- **Stager path traversal.** A profile-declared `stager.path`
  that resolves to a route the listener has not registered, or
  that lets a request reach `_stage` with a payload name the
  operator did not intend. The listener registers the path
  verbatim and requires a `?name=` query parameter; a request
  that serves a payload outside the operator's intent is in
  scope.
- **Concurrent-profile path collision.** A profile whose
  `beacon_path`, `tasks_path`, or `results_path` collides with
  another loaded profile's path. The listener registers a route
  per path and refuses a profile whose paths collide; a report
  that a request reaches the wrong profile's shape is in scope.
- **Status-code range bypass.** A profile-declared status code
  outside 100–599 reaching the HTTP response without the
  listener's range check. The agent reads the same block from
  its embedded profile and compares the actual response code
  against the declared value; a status code that fails the
  comparison but reaches the client anyway is in scope.

#### Resource exhaustion

- **Beacon-listener connection flood.** A malformed or partial
  TLS handshake that bypasses the per-source-IP token bucket and
  exhausts file descriptors before the bucket fires.
- **Operator request flood.** A request that bypasses the
  `MAX_CONCURRENT_PER_OPERATOR` cap or the general rate limiter.
- **Chat flood.** A message that bypasses `CHAT_PER_SEC` or the
  chat-bucket token count.
- **Upload flood.** A loot or chat-file upload that bypasses
  `MAX_TOTAL_BYTES`, `MAX_FILES`, or the per-chunk staging lock.
- **Task-queue flood.** A verb that can be queued without the
  queue cap firing, or a task that can be re-queued by a client
  that no longer owns it.
- **Long-poll starvation.** A long-poll request that holds a
  werkzeug worker thread indefinitely. The
  `MAX_CONCURRENT_PER_OPERATOR` cap is the defence; a long-poll
  that bypasses it is a bug.

#### Transport-specific

- **DNS chunk reassembly flaws.** A QNAME chunk sequence that
  causes the reassembler to allocate unbounded memory, to write
  outside the transfer buffer, or to accept chunks out of order
  with a size that exceeds the per-chunk ceiling. The transfer
  cap is `CHUNK_MAX`; a chunk sequence that reaches the buffer
  with a size above `payload_chunk_size` is in scope.
- **ICMP data-field parsing flaws.** A magic-prefix collision, a
  malformed JSON envelope, or a chunk sequence that bypasses the
  size cap. The 1400-byte reply data-field cap is the reference;
  a reply above the cap that reaches the client rather than being
  dropped is in scope.
- **QUIC stream handling flaws.** A stream that bypasses the
  HTTP/3 body cap, a request smuggling vector on the QUIC
  carriage, or a stream reset that leaves state behind. The QUIC
  listener subclasses `BeaconListener`; a report that a request
  reaches the Flask app without going through the shared
  session-cookie logic is in scope.
- **WebSocket frame handling flaws.** A frame that bypasses the
  JSON envelope size cap, a path that reaches the dispatcher
  without an accepted route, an upgrade that bypasses the peer
  identity check the HTTP listener performs, or a `Set-Cookie`
  extraction that reads a cookie name other than the profile's
  `cookie_name`. The dispatcher's `cname` variable is the
  reference; a report that it reads a different name than the
  listener wrote is in scope.
- **WireGuard handshake flaws.** A handshake initiation from a
  peer whose public key is not pinned, a tunnel IP assignment
  that collides with an existing peer, or an inner HTTPS
  connection that bypasses the pinned CA or the mTLS client
  certificate. The server's WireGuard device silently drops
  unknown peers; a report that a request reaches the inner
  listener from an unpinned peer is in scope.
- **DoH query shaping flaws.** A `dns_label` verb character that
  makes two different verbs indistinguishable on the DoH
  carriage, or a resolver-side query that reaches the C2's
  authoritative NS with a verb the listener refuses to dispatch.
  The DNS and DoH transports share the same QNAME format; a
  change that makes them diverge is in scope.
- **Failover-ring state confusion.** A transport rotation that
  leaves the previous transport's session cookie, ephemeral
  ECDH key, or shaping state live on the new transport, so the
  new transport accepts a message the old transport's peer sent.
  The failover ring is built around the HTTP transport's
  headers; a report that a multi-transport build (`http,dns`,
  `http,doh`, `dns,doh`) confuses state between two transports
  is in scope.
- **Single-transport-only enforcement.** A build that selects
  `quic`, `websocket`, or `wireguard` alongside another
  transport. The builder refuses the combination; a report that
  a build reaches the agent with two of them and produces a
  binary that tries to use both is in scope.

#### Dead-man's switch

- **Unauthorized halt.** A halt sequence that runs without a
  guardian credential, without the two-second remote defer, or
  without the audit entry being written before the wipe.
- **Wipe-scope escape.** A `_cleanup_state` path that removes a
  directory outside the `TornadoC2` tree — a symlink that
  resolves outside, a hard link that crosses filesystems, or a
  `$HOME` that happens to sit under the tree. The safety rails
  are the reference; a report should demonstrate a specific path
  that escapes them.
- **Crypto-mode scope mistake.** A `crypto` mode that destroys a
  LUKS header without the operator confirmation, or that
  destroys a header on a volume other than the one holding the
  tree. This is the most destructive failure mode in the project;
  report it with a reproduction even if the reproduction requires
  a specific filesystem layout.
- **Wipe-scope regression from a new state directory.** A new
  feature that writes a state file outside `logs/` without
  adding the path to the wipe list. `logs/` is picked up
  automatically by the scope check; a state directory outside
  it is not.
- **Fail-safe regression.** A malformed `deadman.json` that
  enables the switch rather than disabling it, or a cleanup
  error that leaves the process running rather than reaching
  `os._exit(1)`. Both are deliberate fail-safe choices; a
  change that reverses either is a bug.

#### Supply chain

- **Agent-side direct dependencies.** The agent's module graph
  resolves six direct dependencies:

  - `github.com/miekg/dns` — DNS and DoH transports
  - `github.com/quic-go/quic-go` — QUIC / HTTP/3 transport
  - `github.com/coder/websocket` — WebSocket transport
  - `github.com/chrj/wgnet` — WireGuard transport
  - `github.com/refraction-networking/utls` — browser TLS
    ClientHello fingerprinting
  - `github.com/tetratelabs/wazero` — WASM extension host

  A vulnerability in any of them that has a specific impact on
  TornadoC2's threat model is in scope; a general vulnerability
  in one of them is better reported upstream. The `go.mod` pin is
  the reference — a report that a build pulls a version other
  than the pinned one is in scope.

- **Handler-side direct dependencies.** The handler's Python
  dependencies are `flask`, `cryptography`, `dnslib`, `aioquic`,
  `simple-websocket`, and `pyroute2`. The operator client
  additionally depends on `cryptography`, and optionally on
  `PySide6` for the GUI. The same reasoning applies.

- **Build-script compromise.** `install-go-build.sh` downloads
  `garble` at a pinned version. A report that the pin has been
  silently overridden, or that the script fetches anything else
  at run time, is in scope.

- **Release-channel compromise.** The project does not use
  release tags; every contribution lands as a commit on `main`.
  A report that a commit was pushed without maintainer review, or
  that a fork is being distributed as the canonical repository,
  is in scope.

### What is *not* a vulnerability

Stated so the above is read with the right scope. The following
will be closed with an explanation, not investigated:

- **Misuse of the tool.** Using TornadoC2 on a system you do not
  have authorization to test is not a framework flaw.
- **A compromised operator machine.** If an attacker owns the
  operator's workstation, every capability the operator holds is
  theirs. TornadoC2 cannot defend against a hostile endpoint.
- **A compromised team server.** An attacker with root on the
  team server holds every key, every config, and every audit
  record. Full-disk encryption and physical control are the only
  mitigations, and both are outside the project's scope.
- **A weak operator password.** The password second factor
  protects against a leaked `.cfg`. It does not protect against
  an operator who chooses `admin123`.
- **Physical seizure of a running machine.** The dead-man's switch
  is best-effort; see the README's "What no software can protect
  against" section.
- **EDR detection.** The project does not claim to evade EDR,
  AMSI, ScriptBlock logging, memory forensics, or QUIC / WebSocket
  / WireGuard ClientHello fingerprinting. A report that
  "Defender caught it" is not a security report; it is a
  detection report.
- **A malicious WASM extension the operator loaded on purpose.**
  An extension is Python-equivalent code with the four host
  functions as its entire surface. Loading one from an
  untrusted source is the operator's choice. A flaw in the
  *loading* mechanism — the extension the operator loaded is
  not the extension that ran — is in scope; the extension
  doing what it said it would do is not.
- **A malicious BOF the operator registered on purpose.** Same
  reasoning. The registry is a blob broker; the operator decides
  what to register and what to run.
- **A malicious C2 profile the operator named on purpose.** A
  profile is a trust-boundary input the operator chooses. A
  profile that declares a suspicious User-Agent or a shaping
  block that mimics an unusual service is the operator's choice.
  A flaw in the *validation* of a profile — one that reaches
  the wire without the checks in
  [C2 Profile Trust](#c2-profile-trust) firing — is in scope.
- **A malicious redirector in front of the beacon listener.**
  The redirector is operator infrastructure, outside the
  project's trust boundary.
- **An operator who copied what they saw.** Chat is a transport,
  not a control. A DM that the recipient republishes is not a
  framework flaw.
- **A leaked audit log.** `logs/audit/` is not encrypted at rest.
  A defender who reads it reads everything the operators did.
  This is documented.
- **A leaked `logs/creds.json`, `logs/lootstore/`, or
  `logs/chat/files/`.** Same reasoning. The vault, the loot
  store, and the chat file store are not encrypted at rest.
- **A leaked `team_ca/` directory.** Same reasoning. The team CA
  is a long-lived secret the operator is expected to protect; the
  README documents what a compromise of it means.
- **No hot-reload of profiles or transports on the handler.**
  Profiles are read once at startup and never again. A change
  that reloads a profile at runtime would silently invalidate
  every deployed agent built against the old shape. The absence
  of hot-reload is a design choice; a report that it is missing
  is not a security report.
- **The single-transport-only restriction on WebSocket, QUIC, and
  WireGuard.** The failover ring is built around the HTTP
  transport's headers, and each of those transports carries its
  own session-cookie handling path. The restriction is a design
  choice.
- **The absence of persistence on the target.** The agent has no
  persistence mechanism by design. A report that a beacon does
  not survive a reboot is not a security report.
- **The absence of an interactive shell.** The beacon is a
  pull-based implant; it does not hold a socket. This is a
  design boundary, not a gap.

---

## External Extension Trust

WASM extensions run inside the agent's sandbox and can only call
the four host functions. They cannot open a socket, spawn a
process, or read a file outside what `host_read` can reach. They
cannot change the agent's on-disk hash.

Operators should only load extensions from trusted sources. A
malicious extension intentionally loaded by an operator is not
considered a framework vulnerability.

However, a flaw in the **loading mechanism** that lets an
extension run in place of the one the operator named — a path
substitution, a name collision with a native verb, or a cache
that returns the wrong module — is a security issue and falls
under the sandbox category above.

**Extensions are HTTP-only in practice.** A WASM module delivered
over DNS is capped at roughly 47 KiB after base64 inflation, which
is smaller than any useful module; ICMP caps a reply at 1400
bytes. A module that does not fit through a transport's ceiling
does not reach the beacon that transport carries. The framework
does not attempt to enforce this — it is an operational
constraint, not a security boundary — but a report that the
agent accepts a partial module and runs it is in scope.

---

## C2 Profile Trust

A C2 profile is JSON the operator chooses. The operator is
responsible for the profile's content — a profile that mimics a
service the target network does not expect, or that declares a
suspicious User-Agent, is a detection risk the operator accepts.

The framework's responsibility is narrower: **a profile must not
be able to reach the wire in a state the agent or the listener
did not intend.** The following checks are in place and are the
reference for what counts as a validation failure:

- **Shape round-trip.** The agent's `ValidateShapingSpec` renders
  a probe payload through each shape's template, walks the
  extract path, and verifies the payload comes back unchanged.
  A shape that fails the round-trip is refused at build time.
- **Distinct paths per role.** `beacon_path`, `tasks_path`, and
  `results_path` must be three different strings. The listener
  registers one route per path and shapes one role per route; a
  collision registers one route and shapes one role, and the
  profile is refused at load time.
- **Path collision across profiles.** Two loaded profiles cannot
  declare the same path for the same role. The listener refuses
  a profile whose paths collide with an already-loaded profile's
  paths, and the profile fails to load with a specific error
  naming the collision.
- **No query strings in paths.** Flask matches against
  `request.path` with the query string stripped. A profile whose
  path carries a query string registers a route that does not
  match anything the handler sees.
- **Status-code range.** A profile-declared status code outside
  100–599 is refused at load time. The agent reads the same
  block from its embedded profile and compares the actual
  response code against the declared value.
- **Cookie-name character class.** A profile-declared
  `cookie_name` containing characters outside `[A-Za-z0-9._-]` is
  refused; the field falls through to `sid`.
- **Response-header character class.** A profile-declared
  `response_headers` entry whose name or value carries `\r`,
  `\n`, or `\0` is dropped; the response is sent without that
  header rather than refused. The profile's `response_headers`
  are merged after the framework-set headers — the profile can
  override `Server` and `Cache-Control` but not the ones the C2
  protocol depends on.
- **DNS verb characters.** Each `dns_label` verb must be a
  single lowercase alphanumeric character. A collision — the
  same character for two different verbs — resets all three
  verbs to `b`/`t`/`r` at once, on both sides. The listener and
  the agent must agree on the reset, or the query reaches the
  wrong handler.
- **DNS chunk size.** A `payload_chunk_size` outside 1–63 falls
  through to 63 on both sides. The chunk label cannot exceed
  the DNS label maximum.
- **Stager path.** A `stager.path` that does not start with `/`
  is refused. The listener registers the declared path verbatim
  and requires a `?name=` query parameter.
- **Placement fallback.** An unsupported `placement.kind`, or a
  name that fails character-class validation, falls through to
  `body` rather than refusing the profile. A profile that
  declared a placement the transport does not support is
  documented behaviour, not a validation failure — but a report
  that the fallback leaves the payload in a location the agent
  does not read is in scope.

A profile that reaches the wire without one of these checks
firing is in scope for a security report. A profile that passes
all of them and turns out to be easy to detect is not.

---

## Reporting Other Bugs

Because the agent relies on native commands and standard-library
behavior that already exists on the target, and the handler runs
on top of Flask/Werkzeug, general bugs are expected. Examples:

- A native verb returning wrong or missing output on a specific
  OS or architecture.
- The listener failing to start on a particular Python version.
- A transport refusing to start because a Python package was
  missing, without naming the package.
- Chunked transfer stalling or failing on a large file.
- The wizard misparsing a flag or failing to compile for a
  supported target.
- Session-reaper behavior forgetting a healthy beacon too early,
  or retaining a dead one too long.
- A pivot child not appearing in `beacons` after the parent
  checks in.
- A `migrate` failure on a specific target OS.
- A C2 profile whose build-time validation passes but whose
  shaping the agent fails to unwrap at runtime. Include the
  profile JSON.
- A `dns_label` block the builder did not emit into the agent's
  linker flags, or that the listener did not pick up from the
  same profile.
- A multi-transport build (`http,dns`, `http,doh`, `dns,doh`)
  that does not rotate to the next transport when it should, or
  that rotates when it should not.
- GUI rendering glitches, PySide6 startup failures, or
  input-routing bugs in the Log or Chat tabs.
- Help text, completion, or UI glitches.

For these, **open a regular GitHub Issue** (without the
`security` label). Include:

- The target OS and CPU architecture.
- The operator OS, Python version, and CPU architecture.
- The Go toolchain version (from `go version`).
- Which transports were enabled at the handler, and which were
  built into the agent.
- Whether the beacon was built with `--verbose`.
- The exact command or wizard path you ran.
- Any error messages, logs, or agent stderr returned.
- For pivot bugs: whether the parent, the child, or the team
  server is the affected component, and whether the transport is
  SMB or TCP.
- For C2 profile bugs: the profile name, the shaping block, and
  whether the build-time validation passed.
- For GUI bugs: the Qt platform plugin in use (`xcb`, `wayland`,
  or `offscreen`), the PySide6 version
  (`python -c "import PySide6; print(PySide6.__version__)"`),
  and whether the same command works through the CLI.

---

## Disclosure Process

1. **Preferred:** use GitHub's **Private vulnerability reporting**
   (the repository's **Security** tab → **Report a
   vulnerability**). This keeps all details confidential until a
   fix is published.
2. **Alternative:** if the private reporting channel is
   unavailable, contact the maintainers through the address
   listed in the repository's profile.
3. You will receive an acknowledgement within **48 hours**.
4. You will receive a status update — investigating, confirmed,
   declined, or need-more-info — within **5 business days**.
5. If the vulnerability is confirmed:
   - A fix is pushed to `main` as soon as it can be written and
     reviewed.
   - A security advisory is published on the repository
     describing the impact in the abstract, not the exploit
     detail.
   - You are credited in the fix commit and in the advisory,
     unless you ask to remain anonymous.
6. If the report is declined:
   - The reasoning is stated explicitly. "Out of scope" is not a
     sufficient answer; the report will point at the README
     section, the design decision, or the category in this
     document that applies.
   - If you disagree with the decline, you are welcome to argue
     the point. A declined report that turns out to be a real
     vulnerability later is a bug on the maintainers' side, not
     yours.

Please do not open a public issue, a public pull request, or a
public discussion thread about a suspected vulnerability before
the disclosure process has run its course. A public issue is a
zero-day disclosure, and the project treats it as such.

---

## Operator OPSEC Warning

The handler stores commands, task output, session metadata,
credential values, chat history, loot, and audit entries under
`logs/`. Some of that data is operator-authored; a substantial
portion is target-authored.

Because targets may be compromised by a third party, **logged
data must be considered potentially attacker-controlled as well
as sensitive.** A target that knows it is being operated on can
craft output designed to attack the next person who reads it.

Logs may contain:

- Internal IP addresses, subnet layout, and reachable hosts.
- Usernames, hostnames, domain names, and file paths.
- Credentials, NT hashes, Kerberos keys, tickets, and bearer
  tokens.
- Certificate private keys and SSH private keys.
- Terminal control characters, escape sequences, and other
  terminal-state attacks.
- Maliciously crafted output from a compromised target.

Do not execute, render, or otherwise process untrusted log data
in security-sensitive environments without appropriate
precautions. In particular:

- Do not `cat` a `logs/b<id>_*/session.log` directly to a terminal
  you care about; the file may contain escape sequences. Use a
  viewer that renders them inert, or pipe through a filter.
- Do not render an unredacted `logs/audit/combined.txt` in a
  context where an escape sequence could do damage.
- Do not publish unredacted engagement logs, chat history, loot,
  or credential-vault exports. When reporting a non-security bug,
  sanitize sensitive and identifying information before including
  log excerpts.

The chat sanitizer is the reference for how a target-supplied
string should be handled before it reaches a terminal. Every
other rendering path — task output, aliases, notes, loot
metadata, BOF names, C2 profile descriptions — is expected to
meet the same bar. If you find a path that does not, that is a
security report, not a general bug.

**Chat files and loot are also target-authored.** A chat file
uploaded by one operator and downloaded by another travels
through the server unmodified; the client verifies SHA-256 but
does not sanitize the file's content. A loot blob carries the
same warning — the server stores bytes, it does not inspect
them. An operator who downloads and executes a loot or chat file
from an engagement is trusting the uploader, not the server.

**The audit chain's forensic-preservation entries carry raw
input.** When the chat sanitizer modifies a body — stripped
bytes, NFC length change, or combining-mark drop — the chain
records a second `chat.message` entry with the base64 of the raw
input alongside the clean form. The b64 field is capped at ~2250
bytes, but within that cap the raw bytes are preserved verbatim.
A report that reads the chain with a viewer that renders escape
sequences is reading bytes the sanitizer has already removed
from every operator's live view. The `audit chat` client command
truncates `detail` at 100 characters before the `raw_b64` field;
`grep`-ing the chain file directly is the source of truth when
the raw form is needed as evidence — and the same caution about
rendering untrusted bytes applies.

---

## A Final Note on Scope

TornadoC2 is a pull-based C2 with a compile-time-configured
agent, an ECDSA-signed task channel, a P-256 ECDH wire envelope,
an AEAD-protected pivot model, and a hash-chained audit log. The
project's security posture depends on those layers remaining
intact together. A report that shows one of them can be bypassed
is a report the project wants.

A report that the framework is "detectable", that a specific
EDR product flags a specific technique, or that the agent's Go
runtime has a fingerprint is not a security report. Those are
detection research, which is valuable, and which the README's
honest-limitations sections already acknowledge.

The nine transports in the tree — HTTPS, QUIC, WebSocket, DNS,
DoH, ICMP, WireGuard, SMB pivot, and TCP bind — share the same
security-critical layers (task signing, wire envelope, session
cookie, audit chain). A new transport contributed by the
community is expected to use those layers unchanged; a transport
that reaches the wire without one of them is a report the project
wants, regardless of whether the transport itself is in-tree.

Thank you for taking the time to read this and for reporting
responsibly. Every good report makes the framework harder to
misuse and safer to operate.