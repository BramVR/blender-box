package uiaction

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"unicode"
	"unicode/utf8"
)

const (
	Capability          = "blender-ui-events-v1"
	MaxActions          = 64
	MaxTextScalars      = 256
	MaxTotalTextScalars = 1024
	MaxTimeoutSeconds   = 30
	MaxCoordinate       = 32767
	MaxActionSeconds    = 5
	EvidencePath        = "result/ui-actions.json"
	BeforePath          = "screenshots/blender-window-before-actions.png"
	AfterPath           = "screenshots/blender-window-after-actions.png"
)

type Kind string

const (
	Click Kind = "click"
	Key   Kind = "key"
	Text  Kind = "text"
)

type Button string
type Modifier string

type ClickAction struct {
	X      int    `json:"x"`
	Y      int    `json:"y"`
	Button Button `json:"button"`
}
type KeyAction struct {
	Key       string     `json:"key"`
	Modifiers []Modifier `json:"modifiers,omitempty"`
}

// Variant fields stay private so callers cannot build mixed action shapes.
type Action struct {
	kind  Kind
	click ClickAction
	key   KeyAction
	text  string
}

func (a Action) Kind() Kind { return a.kind }
func (a Action) TextScalars() int {
	if a.kind == Text {
		return utf8.RuneCountInString(a.text)
	}
	return 0
}

type Batch struct {
	SchemaVersion  int      `json:"schema_version"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	Actions        []Action `json:"actions"`
}

func (b *Batch) UnmarshalJSON(data []byte) error {
	type wire Batch
	var decoded wire
	if strictJSON(data, &decoded) != nil {
		return fmt.Errorf("invalid UI action batch JSON")
	}
	*b = Batch(decoded)
	return b.Validate()
}
func (b Batch) Validate() error {
	if b.SchemaVersion != 1 || b.TimeoutSeconds < 1 || b.TimeoutSeconds > MaxTimeoutSeconds || len(b.Actions) < 1 || len(b.Actions) > MaxActions {
		return fmt.Errorf("UI batch requires version 1, 1..64 actions, and timeout_seconds within 1..30")
	}
	total := 0
	for i, a := range b.Actions {
		if err := a.validate(); err != nil {
			return fmt.Errorf("UI action %d: %w", i, err)
		}
		total += a.TextScalars()
	}
	if total > MaxTotalTextScalars {
		return fmt.Errorf("UI batch exceeds 1024 text scalars")
	}
	return nil
}
func (a *Action) UnmarshalJSON(data []byte) error {
	if err := validJSONScalars(data); err != nil {
		return err
	}
	var tag struct {
		Type Kind `json:"type"`
	}
	if json.Unmarshal(data, &tag) != nil {
		return fmt.Errorf("invalid UI action JSON")
	}
	var next Action
	next.kind = tag.Type
	switch tag.Type {
	case Click:
		var w struct {
			Type   Kind   `json:"type"`
			X      *int   `json:"x"`
			Y      *int   `json:"y"`
			Button Button `json:"button"`
		}
		if strictJSON(data, &w) != nil || w.X == nil || w.Y == nil {
			return fmt.Errorf("invalid click action fields")
		}
		next.click = ClickAction{*w.X, *w.Y, w.Button}
	case Key:
		var w struct {
			Type      Kind       `json:"type"`
			Key       string     `json:"key"`
			Modifiers []Modifier `json:"modifiers,omitempty"`
		}
		if strictJSON(data, &w) != nil {
			return fmt.Errorf("invalid key action fields")
		}
		next.key = KeyAction{w.Key, w.Modifiers}
	case Text:
		var w struct {
			Type Kind   `json:"type"`
			Text string `json:"text"`
		}
		if strictJSON(data, &w) != nil {
			return fmt.Errorf("invalid text action fields")
		}
		next.text = w.Text
	default:
		return fmt.Errorf("unknown UI action type")
	}
	if err := next.validate(); err != nil {
		return err
	}
	*a = next
	return nil
}
func (a Action) MarshalJSON() ([]byte, error) {
	switch a.kind {
	case Click:
		return json.Marshal(struct {
			Type Kind `json:"type"`
			ClickAction
		}{a.kind, a.click})
	case Key:
		return json.Marshal(struct {
			Type Kind `json:"type"`
			KeyAction
		}{a.kind, a.key})
	case Text:
		return json.Marshal(struct {
			Type Kind   `json:"type"`
			Text string `json:"text"`
		}{a.kind, a.text})
	default:
		return nil, fmt.Errorf("invalid UI action")
	}
}
func (a Action) validate() error {
	switch a.kind {
	case Click:
		if a.click.X < 0 || a.click.Y < 0 || a.click.X > MaxCoordinate || a.click.Y > MaxCoordinate || (a.click.Button != "left" && a.click.Button != "middle" && a.click.Button != "right") {
			return fmt.Errorf("click requires client coordinates within 0..32767 and left, middle, or right button")
		}
	case Key:
		if !validKey(a.key.Key) {
			return fmt.Errorf("unsupported UI key")
		}
		seen := map[Modifier]bool{}
		for _, m := range a.key.Modifiers {
			if (m != "ctrl" && m != "shift" && m != "alt") || seen[m] {
				return fmt.Errorf("invalid or duplicate UI modifier")
			}
			seen[m] = true
		}
	case Text:
		if !utf8.ValidString(a.text) || a.TextScalars() < 1 || a.TextScalars() > MaxTextScalars {
			return fmt.Errorf("text requires 1..256 Unicode scalars")
		}
		for _, r := range a.text {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
				return fmt.Errorf("text contains an unsupported scalar")
			}
		}
	default:
		return fmt.Errorf("invalid UI action")
	}
	return nil
}
func validKey(key string) bool {
	if len(key) == 1 && ((key[0] >= 'A' && key[0] <= 'Z') || (key[0] >= '0' && key[0] <= '9')) {
		return true
	}
	switch key {
	case "ENTER", "ESC", "TAB", "SPACE", "BACKSPACE", "DELETE", "LEFT", "RIGHT", "UP", "DOWN", "HOME", "END", "PAGEUP", "PAGEDOWN":
		return true
	}
	if len(key) > 1 && key[0] == 'F' {
		n, e := strconv.Atoi(key[1:])
		return e == nil && n >= 1 && n <= 12 && key == "F"+strconv.Itoa(n)
	}
	return false
}
func strictJSON(data []byte, out any) error {
	if err := validJSONScalars(data); err != nil {
		return err
	}
	if err := uniqueJSONFields(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

type Outcome string

const (
	Pending   Outcome = "pending"
	Queued    Outcome = "queued"
	Rejected  Outcome = "rejected"
	Uncertain Outcome = "uncertain"
)

type Window struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}
type Receipt struct {
	Index      int     `json:"index"`
	Kind       Kind    `json:"kind"`
	Outcome    Outcome `json:"outcome"`
	SessionID  string  `json:"session_id"`
	Window     *Window `json:"window,omitempty"`
	EventCount int     `json:"event_count"`
	ErrorCode  string  `json:"error_code,omitempty"`
}
type Journal struct {
	SchemaVersion int       `json:"schema_version"`
	Receipts      []Receipt `json:"receipts"`
}

func (r Receipt) Validate(session string) error {
	if r.Index < 0 || r.Index >= MaxActions || r.SessionID != session || session == "" || (r.Kind != Click && r.Kind != Key && r.Kind != Text) || r.EventCount < 0 || r.EventCount > MaxTextScalars*2+8 {
		return fmt.Errorf("invalid UI receipt identity or event count")
	}
	if r.Window != nil && (r.Window.Width < 1 || r.Window.Height < 1 || r.Window.Width > MaxCoordinate+1 || r.Window.Height > MaxCoordinate+1) {
		return fmt.Errorf("invalid UI window dimensions")
	}
	switch r.Outcome {
	case Queued:
		if r.ErrorCode != "" || r.EventCount == 0 || r.Window == nil {
			return fmt.Errorf("invalid queued UI receipt")
		}
	case Pending:
		if r.ErrorCode != "" || r.EventCount != 0 {
			return fmt.Errorf("invalid pending UI receipt")
		}
	case Rejected, Uncertain:
		if r.Outcome == Rejected && r.EventCount != 0 {
			return fmt.Errorf("rejected UI action has events")
		}
		if !validErrorCode(r.ErrorCode) {
			return fmt.Errorf("invalid failed UI receipt")
		}
	default:
		return fmt.Errorf("invalid UI outcome")
	}
	return nil
}

func (j Journal) Validate(session string) error {
	if j.SchemaVersion != 1 || len(j.Receipts) > MaxActions {
		return fmt.Errorf("invalid UI journal")
	}
	for i, r := range j.Receipts {
		if err := r.Validate(session); err != nil {
			return err
		}
		if r.Index != i {
			return fmt.Errorf("UI journal indices are not contiguous")
		}
		if r.Outcome != Queued && i != len(j.Receipts)-1 {
			return fmt.Errorf("UI journal continues after an unsettled action")
		}
	}
	return nil
}
func validErrorCode(code string) bool {
	switch code {
	case "focus-lost", "window-replaced", "window-ambiguous", "out-of-bounds", "stale-session", "cancelled", "timed-out", "delivery-failed", "delivery-unknown", "unsupported", "coordinate-mismatch":
		return true
	}
	return false
}
func (j *Journal) MarkUncertain() {
	if len(j.Receipts) > 0 {
		last := &j.Receipts[len(j.Receipts)-1]
		if last.Outcome == Pending {
			last.Outcome = Uncertain
			last.ErrorCode = "delivery-unknown"
		}
	}
}

func ValidateProgress(previous, next *Journal) error {
	if previous == nil {
		return nil
	}
	if next == nil || len(next.Receipts) < len(previous.Receipts) {
		return fmt.Errorf("UI journal prefix disappeared")
	}
	for i, old := range previous.Receipts {
		current := next.Receipts[i]
		if old.Outcome == Pending {
			if old.Index != current.Index || old.Kind != current.Kind || old.SessionID != current.SessionID {
				return fmt.Errorf("pending UI action identity changed")
			}
		} else {
			oldJSON, _ := json.Marshal(old)
			newJSON, _ := json.Marshal(current)
			if !bytes.Equal(oldJSON, newJSON) {
				return fmt.Errorf("UI journal history changed")
			}
		}
	}
	return nil
}

func (a Action) EventCount() int {
	switch a.kind {
	case Click:
		return 3
	case Key:
		return 2 + 2*len(a.key.Modifiers)
	case Text:
		return 2 * a.TextScalars()
	}
	return 0
}

func uniqueJSONFields(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return fmt.Errorf("duplicate JSON field")
			}
			seen[name] = true
			if err := uniqueJSONFields(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := uniqueJSONFields(decoder); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}

func validJSONScalars(data []byte) error {
	if !utf8.Valid(data) || !json.Valid(data) {
		return fmt.Errorf("invalid UI action JSON encoding")
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if data[i] != 'u' {
			continue
		}
		scalar, _ := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		i += 4
		if scalar >= 0xdc00 && scalar <= 0xdfff {
			return fmt.Errorf("unpaired UI action JSON surrogate")
		}
		if scalar >= 0xd800 && scalar <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return fmt.Errorf("unpaired UI action JSON surrogate")
			}
			low, _ := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if low < 0xdc00 || low > 0xdfff {
				return fmt.Errorf("unpaired UI action JSON surrogate")
			}
			i += 6
		}
	}
	return nil
}
