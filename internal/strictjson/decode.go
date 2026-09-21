package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Decode rejects ambiguous object keys as well as unknown fields and trailing values.
func Decode(content []byte, value any) error {
	tokens := json.NewDecoder(bytes.NewReader(content))
	if err := scan(tokens); err != nil {
		return err
	}
	if _, err := tokens.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON value")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func scan(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		if token == nil {
			return fmt.Errorf("null is not allowed")
		}
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]bool)
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || !canonicalKey(key) || keys[key] {
				return fmt.Errorf("duplicate or invalid JSON key")
			}
			keys[key] = true
			if err := scan(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scan(decoder); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}

func canonicalKey(key string) bool {
	if key == "" {
		return false
	}
	for _, character := range key {
		if character != '_' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}
