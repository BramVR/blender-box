package target

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

const publicKeyFixture = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"

func TestPairedTargetRoundTripBothPlatformsAndStrictSchema(t *testing.T) {
	for _, original := range []Target{fixtureTarget(t), linuxTarget(t)} {
		t.Run(original.Platform(), func(t *testing.T) {
			before, _ := original.MarshalJSON()
			fingerprint := original.Fingerprint()
			direct := DirectSSH{"host.invalid", 2222, "operator", publicKeyFixture, strings.Repeat("1", 64)}
			paired, err := NewPaired(original, direct)
			if err != nil {
				t.Fatal(err)
			}
			data, err := paired.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := Decode(data)
			if err != nil || decoded.Fingerprint() != paired.Fingerprint() {
				t.Fatalf("paired roundtrip: %v", err)
			}
			if string(data) == string(before) || paired.Fingerprint() == fingerprint || strings.Contains(string(data), "ssh_alias") {
				t.Fatal("paired target lost its connection authority")
			}
			if value, _ := original.MarshalJSON(); string(value) != string(before) || original.Fingerprint() != fingerprint {
				t.Fatal("pairing changed original target")
			}
			store := Store{Root: filepath.Join(t.TempDir(), "private")}
			if _, err := store.Save("paired", paired, false); err != nil {
				t.Fatal(err)
			}
			loaded, err := store.Resolve("paired")
			if err != nil || loaded.Fingerprint() != paired.Fingerprint() {
				t.Fatalf("saved pairing: %v", err)
			}
			var wire map[string]any
			if err := json.Unmarshal(data, &wire); err != nil {
				t.Fatal(err)
			}
			wire["ssh_alias"] = "fallback"
			invalid, _ := json.Marshal(wire)
			if _, err := Decode(invalid); err == nil {
				t.Fatal("paired alias fallback accepted")
			}
			delete(wire, "ssh_alias")
			delete(wire, "ssh")
			invalid, _ = json.Marshal(wire)
			if _, err := Decode(invalid); err == nil {
				t.Fatal("missing paired connection accepted")
			}
		})
	}
}
func TestConnectionRejectsUnsafeEndpointAndMutableAuthority(t *testing.T) {
	base := DirectSSH{"host.invalid", 2222, "operator", publicKeyFixture, strings.Repeat("1", 64)}
	for _, mutate := range []func(*DirectSSH){func(d *DirectSSH) { d.Host = "-option" }, func(d *DirectSSH) { d.Host = "host\nProxyCommand command" }, func(d *DirectSSH) { d.User = "other user" }, func(d *DirectSSH) { d.Port = 0 }, func(d *DirectSSH) { d.HostPublicKey += " comment" }, func(d *DirectSSH) { d.ClientPublicKeyHash = "" }} {
		invalid := base
		mutate(&invalid)
		if _, err := PairedConnection(invalid); err == nil {
			t.Fatal("unsafe paired connection accepted")
		}
	}
	connection, err := PairedConnection(base)
	if err != nil {
		t.Fatal(err)
	}
	copy, _ := connection.Direct()
	copy.Host = "replacement.invalid"
	unchanged, _ := connection.Direct()
	if unchanged != base {
		t.Fatal("connection exposed mutable authority")
	}
}
