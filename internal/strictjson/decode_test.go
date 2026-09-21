package strictjson

import "testing"

func TestDecodeRejectsCaseFoldedAndDuplicateKeys(t *testing.T) {
	for _, input := range []string{
		`{"schema_version":1,"SCHEMA_VERSION":2}`,
		`{"SCHEMA_VERSION":1}`,
		`{"ſchema_version":1}`,
		`{"schema_version":1,"schema_\u0076ersion":2}`,
		`{"schema_version":null}`,
		`{"schema_version":1} {}`,
	} {
		var record struct {
			SchemaVersion int `json:"schema_version"`
		}
		if err := Decode([]byte(input), &record); err == nil {
			t.Fatalf("ambiguous keys accepted: %s", input)
		}
	}
}
