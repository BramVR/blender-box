package pairing

import (
	"strings"
	"testing"
)

func TestParseRevokeResultAcceptsOnlyConfirmedRevocationOfThatPair(t *testing.T) {
	hash := strings.Repeat("a", 64)
	valid := `{"schema_version":1,"pair_id":"p1","state":"revoked","keys_sha256_before":"` + hash + `","keys_sha256_after":"` + hash + `","tombstone_sha256":"` + hash + `"}`
	if result, err := ParseRevokeResult([]byte(valid), "p1"); err != nil || result.State != "revoked" {
		t.Fatalf("valid result = %+v, %v", result, err)
	}
	for name, data := range map[string]string{
		"other pair":    valid,
		"not revoked":   strings.Replace(valid, `"revoked"`, `"revoking"`, 1),
		"missing hash":  strings.Replace(valid, `"keys_sha256_after":"`+hash+`",`, "", 1),
		"unknown field": strings.Replace(valid, `{`, `{"extra":1,`, 1),
	} {
		pair := "p1"
		if name == "other pair" {
			pair = "p2"
		}
		if _, err := ParseRevokeResult([]byte(data), pair); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
