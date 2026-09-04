package uiaction

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStrictBoundedActions(t *testing.T) {
	good := []string{`{"type":"click","x":0,"y":1,"button":"left"}`, `{"type":"key","key":"A","modifiers":["ctrl"]}`, `{"type":"text","text":"é漢🙂"}`}
	for _, raw := range good {
		var action Action
		if err := json.Unmarshal([]byte(raw), &action); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(action)
		if err != nil {
			t.Fatal(err)
		}
		var again Action
		if err := json.Unmarshal(encoded, &again); err != nil {
			t.Fatal(err)
		}
	}
	bad := []string{`{"type":"click","x":0,"button":"left"}`, `{"type":"click","x":-1,"y":1,"button":"left"}`, `{"type":"click","x":0,"y":1,"button":"left","text":"secret"}`, `{"type":"key","key":"A","modifiers":["ctrl","ctrl"]}`, `{"type":"key","key":"OSKEY"}`, `{"type":"key","key":"LEFT_CTRL"}`, `{"type":"text","text":"secret\n"}`, `{"type":"text","text":"\ud800"}`, `{"type":"text","text":"` + strings.Repeat("é", 257) + `"}`, `{"type":"text","text":"secret","unknown":true}`}
	for _, raw := range bad {
		var action Action
		err := json.Unmarshal([]byte(raw), &action)
		if err == nil {
			t.Errorf("accepted %s", raw)
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("error leaked text")
		}
	}
}
func TestBatchBudgets(t *testing.T) {
	var a Action
	_ = json.Unmarshal([]byte(`{"type":"text","text":"`+strings.Repeat("é", 256)+`"}`), &a)
	batch := Batch{SchemaVersion: 1, TimeoutSeconds: 30, Actions: []Action{a, a, a, a}}
	if err := batch.Validate(); err != nil {
		t.Fatal(err)
	}
	batch.Actions = append(batch.Actions, a)
	if batch.Validate() == nil {
		t.Fatal("accepted total text overflow")
	}
	batch.Actions = []Action{a}
	batch.TimeoutSeconds = 31
	if batch.Validate() == nil {
		t.Fatal("accepted timeout overflow")
	}
}
func TestJournalAmbiguityNeverBecomesQueued(t *testing.T) {
	j := Journal{SchemaVersion: 1, Receipts: []Receipt{{Index: 0, Kind: Key, Outcome: Queued, SessionID: "exact", Window: &Window{Width: 100, Height: 100}, EventCount: 2}, {Index: 1, Kind: Text, Outcome: Pending, SessionID: "exact"}}}
	if err := j.Validate("exact"); err != nil {
		t.Fatal(err)
	}
	j.MarkUncertain()
	if j.Receipts[1].Outcome != Uncertain || j.Receipts[1].ErrorCode != "delivery-unknown" {
		t.Fatal(j)
	}
	if err := j.Validate("exact"); err != nil {
		t.Fatal(err)
	}
	j.Receipts = append(j.Receipts, Receipt{Index: 2, Kind: Key, Outcome: Pending, SessionID: "exact"})
	if j.Validate("exact") == nil {
		t.Fatal("allowed action after uncertainty")
	}
	if j.Validate("replacement") == nil {
		t.Fatal("accepted replacement Session")
	}
}

func TestReceiptValidationPreservesBoundedActionIndex(t *testing.T) {
	receipt := Receipt{Index: MaxActions - 1, Kind: Key, Outcome: Queued, SessionID: "exact", Window: &Window{Width: 100, Height: 80}, EventCount: 2}
	if err := receipt.Validate("exact"); err != nil {
		t.Fatal(err)
	}
	if receipt.Index != MaxActions-1 {
		t.Fatal("validation changed action index")
	}
	if (Journal{SchemaVersion: 1, Receipts: []Receipt{receipt}}).Validate("exact") == nil {
		t.Fatal("journal accepted a noncontiguous prefix")
	}
	for _, index := range []int{-1, MaxActions} {
		receipt.Index = index
		if receipt.Validate("exact") == nil {
			t.Fatalf("accepted action index %d", index)
		}
	}
}

func TestTextAcceptsReplacementCharacterWithoutReplacingMalformedUnicode(t *testing.T) {
	for _, test := range []struct{ raw, want string }{
		{`{"type":"text","text":"�"}`, "�"},
		{`{"type":"text","text":"\ufffd"}`, "�"},
		{`{"type":"text","text":"\uD83D\uDE42"}`, "🙂"},
		{`{"type":"text","text":"\\ud800"}`, `\ud800`},
	} {
		var action Action
		if err := json.Unmarshal([]byte(test.raw), &action); err != nil {
			t.Fatal(err)
		}
		if action.text != test.want {
			t.Fatalf("text=%q, want %q", action.text, test.want)
		}
	}
	for _, raw := range []string{
		`{"type":"text","text":"private\ud800"}`,
		`{"type":"text","text":"private\udc00"}`,
		`{"type":"text","text":"private\ud800\ufffd"}`,
		`{"type":"text","text":"private\ud800\ud800"}`,
		`{"type":"text","text":"private\ud800x\udc00"}`,
		`{"type":"text","text":"private` + string([]byte{0xff}) + `"}`,
		`{"type":"text","text":"private` + string([]byte{0xed, 0xa0, 0x80}) + `"}`,
	} {
		var action Action
		err := json.Unmarshal([]byte(raw), &action)
		if err == nil {
			t.Fatalf("accepted malformed Unicode %q", raw)
		}
		if strings.Contains(err.Error(), "private") {
			t.Fatal("error leaked text")
		}
		var batch Batch
		if json.Unmarshal([]byte(`{"schema_version":1,"timeout_seconds":10,"actions":[`+raw+`]}`), &batch) == nil {
			t.Fatal("batch accepted malformed Unicode")
		}
	}
}
