package protocol

import (
	"encoding/json"
	"testing"
)

func TestFingerprintStableAndRoleScoped(t *testing.T) {
	a := Identity{MachineID: "m", Hostname: "h",
		Username: "u", OS: "linux"}
	b := a
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("fingerprint not stable")
	}
	b.Privilege = "root"
	b.PID = 42
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("runtime fields changed fingerprint")
	}
	b.IdentityRole = "red"
	if a.Fingerprint() == b.Fingerprint() {
		t.Fatal("identity role must change fingerprint")
	}
}

func TestTaskJSONRoundTrip(t *testing.T) {
	in := Task{ID: "t1", Verb: "sh", Args: []string{"id"}, Timeout: 5}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Task
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.ID != in.ID || out.Verb != in.Verb ||
		len(out.Args) != 1 || out.Args[0] != "id" {
		t.Fatalf("round trip mismatch: %+v", out)
	}
}

func FuzzTaskDecode(f *testing.F) {
	f.Add([]byte(`{"id":"x","verb":"ls","args":[]}`))
	f.Add([]byte(`{"id":1}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var task Task
		_ = json.Unmarshal(raw, &task)
	})
}
