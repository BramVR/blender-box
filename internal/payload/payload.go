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
	if err := validatePortablePath("scenario script", declared.Scenario.Script); err != nil {
		return Payload{}, err
	}

	base := filepath.Dir(path)
	result := Payload{SchemaVersion: 1, Scenario: declared.Scenario}
	destinations := make(map[string]struct{}, len(declared.Files))
	var total int64
	for _, declaredFile := range declared.Files {
		if err := validatePortablePath("source", declaredFile.Source); err != nil {
			return Payload{}, err
		}
		if err := validatePortablePath("destination", declaredFile.Destination); err != nil {
			return Payload{}, err
		}
		if _, exists := destinations[declaredFile.Destination]; exists {
			return Payload{}, fmt.Errorf("duplicate destination %q", declaredFile.Destination)
		}
		destinations[declaredFile.Destination] = struct{}{}

		localPath, info, err := regularFileWithoutSymlinks(base, declaredFile.Source)
		if err != nil {
			return Payload{}, fmt.Errorf("source %q: %w", declaredFile.Source, err)
		}
		if info.Size() > maxFileBytes {
			return Payload{}, fmt.Errorf("source %q exceeds %d bytes", declaredFile.Source, maxFileBytes)
		}
		total += info.Size()
		if total > maxTotalBytes {
			return Payload{}, fmt.Errorf("payload exceeds %d bytes", maxTotalBytes)
		}
		hash, err := hashFile(localPath, maxFileBytes)
		if err != nil {
			return Payload{}, fmt.Errorf("hash source %q: %w", declaredFile.Source, err)
		}
		result.Files = append(result.Files, File{
			Source:      declaredFile.Source,
			Destination: declaredFile.Destination,
			Size:        info.Size(),
			SHA256:      hash,
			LocalPath:   localPath,
		})
	}
	if _, exists := destinations[declared.Scenario.Script]; !exists {
		return Payload{}, fmt.Errorf("scenario script %q is not a declared destination", declared.Scenario.Script)
	}
	return result, nil
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

func validatePortablePath(label, path string) error {
	if path == "" || strings.Contains(path, `\`) || strings.HasPrefix(path, "/") {
		return fmt.Errorf("%s %q is unsafe", label, path)
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if clean != path || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("%s %q is unsafe", label, path)
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

func hashFile(path string, limit int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, limit+1))
	if err != nil {
		return "", err
	}
	if written > limit {
		return "", fmt.Errorf("file grew beyond %d bytes", limit)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
