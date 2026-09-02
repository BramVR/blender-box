package payload

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/BramVR/blender-box/internal/safepath"
)

const (
	maxDocumentBytes = 1 << 20
	maxFiles         = 64
	maxFileBytes     = 8 << 20
	maxTotalBytes    = 32 << 20
	defaultTimeout   = 180
	maxTimeout       = 3600
)

// Payload is the bounded, declared input staged for one Run.
type Payload struct {
	SchemaVersion int      `json:"schema_version"`
	Files         []File   `json:"files,omitempty"`
	Scenario      Scenario `json:"scenario"`
}

// File describes one payload file. LocalPath never crosses the host boundary.
type File struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	LocalPath   string `json:"-"`
	contents    []byte
}

// Contents returns a copy of the bytes validated by Load.
func (file File) Contents() []byte {
	return append([]byte(nil), file.contents...)
}

// Scenario declares the Blender script and bounded daemon call behavior.
type Scenario struct {
	Script             string `json:"script"`
	ReadTimeoutSeconds int    `json:"read_timeout_seconds"`
	CaptureViewport    bool   `json:"capture_viewport"`
}

type document struct {
	SchemaVersion int            `json:"schema_version"`
	Files         []documentFile `json:"files"`
	Scenario      Scenario       `json:"scenario"`
}

type documentFile struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

// Load validates a Run Payload and computes the immutable transfer facts.
func Load(path string) (Payload, error) {
	contents, err := readBounded(path, maxDocumentBytes)
	if err != nil {
		return Payload{}, fmt.Errorf("read payload document: %w", err)
	}
	var declared document
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&declared); err != nil {
		return Payload{}, fmt.Errorf("decode payload document: %w", err)
	}
	if err := requireJSONEnd(decoder); err != nil {
		return Payload{}, err
	}
	if declared.SchemaVersion != 1 {
		return Payload{}, fmt.Errorf("unsupported payload schema version %d", declared.SchemaVersion)
	}
	if len(declared.Files) == 0 || len(declared.Files) > maxFiles {
		return Payload{}, fmt.Errorf("payload file count %d is outside 1..%d", len(declared.Files), maxFiles)
	}
	if declared.Scenario.ReadTimeoutSeconds == 0 {
		declared.Scenario.ReadTimeoutSeconds = defaultTimeout
	}
	if declared.Scenario.ReadTimeoutSeconds < 1 || declared.Scenario.ReadTimeoutSeconds > maxTimeout {
		return Payload{}, fmt.Errorf("scenario read timeout must be within 1..%d seconds", maxTimeout)
	}
	if err := safepath.ValidateWindowsRelative("scenario script", declared.Scenario.Script); err != nil {
		return Payload{}, err
	}

	base := filepath.Dir(path)
	result := Payload{SchemaVersion: 1, Scenario: declared.Scenario}
	destinations := make(map[string]struct{}, len(declared.Files))
	var total int64
	for _, declaredFile := range declared.Files {
		if err := safepath.ValidateWindowsRelative("source", declaredFile.Source); err != nil {
			return Payload{}, err
		}
		if err := safepath.ValidateWindowsRelative("destination", declaredFile.Destination); err != nil {
			return Payload{}, err
		}
		destinationKey := strings.ToLower(declaredFile.Destination)
		if _, exists := destinations[destinationKey]; exists {
			return Payload{}, fmt.Errorf("duplicate destination %q", declaredFile.Destination)
		}
		destinations[destinationKey] = struct{}{}

		localPath, contents, err := readValidatedFile(base, declaredFile.Source)
		if err != nil {
			return Payload{}, fmt.Errorf("source %q: %w", declaredFile.Source, err)
		}
		total += int64(len(contents))
		if total > maxTotalBytes {
			return Payload{}, fmt.Errorf("payload exceeds %d bytes", maxTotalBytes)
		}
		hash := sha256.Sum256(contents)
		result.Files = append(result.Files, File{
			Source:      declaredFile.Source,
			Destination: declaredFile.Destination,
			Size:        int64(len(contents)),
			SHA256:      hex.EncodeToString(hash[:]),
			LocalPath:   localPath,
			contents:    contents,
		})
	}
	if _, exists := destinations[strings.ToLower(declared.Scenario.Script)]; !exists {
		return Payload{}, fmt.Errorf("scenario script %q is not a declared destination", declared.Scenario.Script)
	}
	if err := result.Validate(); err != nil {
		return Payload{}, err
	}
	return result, nil
}

// Validate proves that a Payload still carries bounded bytes produced by Load.
func (payload Payload) Validate() error {
	if payload.SchemaVersion != 1 {
		return fmt.Errorf("unsupported payload schema version %d", payload.SchemaVersion)
	}
	if len(payload.Files) == 0 || len(payload.Files) > maxFiles {
		return fmt.Errorf("payload file count %d is outside 1..%d", len(payload.Files), maxFiles)
	}
	if payload.Scenario.ReadTimeoutSeconds < 1 || payload.Scenario.ReadTimeoutSeconds > maxTimeout {
		return fmt.Errorf("scenario read timeout must be within 1..%d seconds", maxTimeout)
	}
	if err := safepath.ValidateWindowsRelative("scenario script", payload.Scenario.Script); err != nil {
		return err
	}
	destinations := make(map[string]struct{}, len(payload.Files))
	var total int64
	for _, file := range payload.Files {
		if err := safepath.ValidateWindowsRelative("source", file.Source); err != nil {
			return err
		}
		if err := safepath.ValidateWindowsRelative("destination", file.Destination); err != nil {
			return err
		}
		key := strings.ToLower(file.Destination)
		if _, exists := destinations[key]; exists {
			return fmt.Errorf("duplicate destination %q", file.Destination)
		}
		destinations[key] = struct{}{}
		if file.contents == nil {
			return fmt.Errorf("source %q has no validated contents", file.Source)
		}
		if len(file.contents) > maxFileBytes || int64(len(file.contents)) != file.Size {
			return fmt.Errorf("source %q size does not match validated contents", file.Source)
		}
		hash := sha256.Sum256(file.contents)
		if hex.EncodeToString(hash[:]) != file.SHA256 {
			return fmt.Errorf("source %q SHA-256 does not match validated contents", file.Source)
		}
		total += file.Size
		if total > maxTotalBytes {
			return fmt.Errorf("payload exceeds %d bytes", maxTotalBytes)
		}
	}
	if _, exists := destinations[strings.ToLower(payload.Scenario.Script)]; !exists {
		return fmt.Errorf("scenario script %q is not a declared destination", payload.Scenario.Script)
	}
	return nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return contents, nil
}

func requireJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("payload document contains multiple JSON values")
		}
		return fmt.Errorf("decode payload document: %w", err)
	}
	return nil
}

func regularFileWithoutSymlinks(base, portablePath string) (string, os.FileInfo, error) {
	current := base
	for _, component := range strings.Split(portablePath, "/") {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return "", nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", nil, fmt.Errorf("not a regular file without symlinks")
		}
	}
	info, err := os.Stat(current)
	if err != nil {
		return "", nil, err
	}
	if !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("not a regular file")
	}
	return current, info, nil
}

func readValidatedFile(base, portablePath string) (string, []byte, error) {
	path, before, err := regularFileWithoutSymlinks(base, portablePath)
	if err != nil {
		return "", nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return "", nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return "", nil, fmt.Errorf("file changed during validation")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return "", nil, err
	}
	if len(contents) > maxFileBytes {
		return "", nil, fmt.Errorf("file exceeds %d bytes", maxFileBytes)
	}
	if int64(len(contents)) != opened.Size() {
		return "", nil, fmt.Errorf("file changed during validation")
	}
	_, after, err := regularFileWithoutSymlinks(base, portablePath)
	if err != nil || !os.SameFile(opened, after) {
		return "", nil, fmt.Errorf("file changed during validation")
	}
	return path, contents, nil
}
