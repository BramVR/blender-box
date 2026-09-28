package pairing

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

// testPublicKey builds a canonical ssh-ed25519 public key whose 32 key bytes are all fill.
func testPublicKey(fill byte) string {
	wire := make([]byte, 0, 51)
	wire = binary.BigEndian.AppendUint32(wire, 11)
	wire = append(wire, "ssh-ed25519"...)
	wire = binary.BigEndian.AppendUint32(wire, 32)
	for i := 0; i < 32; i++ {
		wire = append(wire, fill)
	}
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(wire)
}

const otherKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl operator@studio"
const rsaKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 bob@laptop"

func TestGrantLineRefusesNonCanonicalInput(t *testing.T) {
	key := testPublicKey(1)
	line, err := grantLine(key, "pair-1")
	if err != nil || line != "restrict "+key+" blender-box-pair:pair-1" {
		t.Fatalf("line=%q err=%v", line, err)
	}
	for _, bad := range [][2]string{{key + " comment", "pair-1"}, {"ssh-rsa AAAA", "pair-1"}, {key, "-pair"}, {key, ""}} {
		if _, err := grantLine(bad[0], bad[1]); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestAppendAndRemovePreserveUnrelatedBytes(t *testing.T) {
	key := testPublicKey(2)
	line, _ := grantLine(key, "pair-2")
	cases := []struct{ name, before, after, restored string }{
		{"empty", "", line + "\n", ""},
		{"lf", otherKey + "\n" + rsaKey + "\n", otherKey + "\n" + rsaKey + "\n" + line + "\n", otherKey + "\n" + rsaKey + "\n"},
		{"crlf", otherKey + "\r\n" + rsaKey + "\r\n", otherKey + "\r\n" + rsaKey + "\r\n" + line + "\r\n", otherKey + "\r\n" + rsaKey + "\r\n"},
		{"unterminated", otherKey + "\n" + rsaKey, otherKey + "\n" + rsaKey + "\n" + line + "\n", otherKey + "\n" + rsaKey + "\n"},
		{"unterminated crlf", otherKey + "\r\n" + rsaKey, otherKey + "\r\n" + rsaKey + "\r\n" + line + "\r\n", otherKey + "\r\n" + rsaKey + "\r\n"},
		{"comments and blanks", "# managed by ops\n\n  \n" + otherKey + "\n\n", "# managed by ops\n\n  \n" + otherKey + "\n\n" + line + "\n", "# managed by ops\n\n  \n" + otherKey + "\n\n"},
		{"options", `no-pty,command="/bin/false" ` + rsaKey + "\n", `no-pty,command="/bin/false" ` + rsaKey + "\n" + line + "\n", `no-pty,command="/bin/false" ` + rsaKey + "\n"},
		{"stock admin file", otherKey + "\n" + "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBvXqvcQzNgW1pDPqS2R8b2Pj3Lm7v0KfAqz1u2Hq9Yk\n", otherKey + "\n" + "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBvXqvcQzNgW1pDPqS2R8b2Pj3Lm7v0KfAqz1u2Hq9Yk\n" + line + "\n", otherKey + "\n" + "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBvXqvcQzNgW1pDPqS2R8b2Pj3Lm7v0KfAqz1u2Hq9Yk\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if exact, foreignKey, foreignMarker := scanKeys([]byte(tc.before), line, key, "pair-2"); exact != 0 || foreignKey || foreignMarker {
				t.Fatalf("before scan %d %v %v", exact, foreignKey, foreignMarker)
			}
			after := appendLine([]byte(tc.before), line)
			if string(after) != tc.after {
				t.Fatalf("append\n got %q\nwant %q", after, tc.after)
			}
			if exact, foreignKey, foreignMarker := scanKeys(after, line, key, "pair-2"); exact != 1 || foreignKey || foreignMarker {
				t.Fatalf("after scan %d %v %v", exact, foreignKey, foreignMarker)
			}
			restored, err := removeLine(after, line)
			if err != nil || string(restored) != tc.restored {
				t.Fatalf("remove err=%v\n got %q\nwant %q", err, restored, tc.restored)
			}
		})
	}
}

func TestRemoveLineKeepsLineInTheMiddleExact(t *testing.T) {
	key := testPublicKey(3)
	line, _ := grantLine(key, "pair-3")
	contents := otherKey + "\r\n" + line + "\r\n" + rsaKey + "\r\n"
	restored, err := removeLine([]byte(contents), line)
	if err != nil || string(restored) != otherKey+"\r\n"+rsaKey+"\r\n" {
		t.Fatalf("err=%v got %q", err, restored)
	}
	if _, err := removeLine([]byte(otherKey+"\n"), line); err == nil {
		t.Fatal("removed a line that was absent")
	}
	if _, err := removeLine([]byte(line+"\n"+line+"\n"), line); err == nil {
		t.Fatal("removed one of two duplicate lines")
	}
}

func TestScanKeysReportsForeignCopiesAndMarkers(t *testing.T) {
	key := testPublicKey(4)
	line, _ := grantLine(key, "pair-4")
	cases := []struct {
		name          string
		contents      string
		exact         int
		foreignKey    bool
		foreignMarker bool
	}{
		{"unmarked copy of the key", key + "\n", 0, true, false},
		{"key under another marker", "restrict " + key + " blender-box-pair:pair-9\n", 0, true, false},
		{"key with a comment", key + " someone@else\n", 0, true, false},
		{"our marker with another key", "restrict " + testPublicKey(5) + " blender-box-pair:pair-4\n", 0, false, true},
		{"commented-out copy is ignored", "# " + line + "\n", 0, false, false},
		{"exact line twice", line + "\n" + line + "\n", 2, false, false},
		{"exact line with cr", line + "\r\n", 1, false, false},
		{"exact line unterminated", otherKey + "\n" + line, 1, false, false},
		{"marker prefix of a longer id", "restrict " + testPublicKey(5) + " blender-box-pair:pair-40\n", 0, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exact, foreignKey, foreignMarker := scanKeys([]byte(tc.contents), line, key, "pair-4")
			if exact != tc.exact || foreignKey != tc.foreignKey || foreignMarker != tc.foreignMarker {
				t.Fatalf("got %d %v %v", exact, foreignKey, foreignMarker)
			}
		})
	}
}
