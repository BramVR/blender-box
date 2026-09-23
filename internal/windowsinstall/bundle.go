package windowsinstall

import (
	"archive/zip"
	"bufio"
	"bytes"
	"debug/pe"
	"fmt"
	"io"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/safepath"
	"github.com/BramVR/blender-box/internal/strictjson"
)

const maxArtifact = 64 << 20
const maxFiles = 2048
const maxExpanded = 128 << 20

type Bundle struct {
	Manifest RuntimeManifest
	SHA256   SHA256
	data     map[ArtifactRole][]byte
	wheel    map[string][]byte
}

func BuildManifest(host, launcher, wheel string, hostSource, daemonSource SourceProvenance) (RuntimeManifest, error) {
	manifest := RuntimeManifest{SchemaVersion: 1, Platform: "windows", Architecture: "amd64", PythonRequires: ">=3.11,<4", DaemonProtocol: "blender-box-v1", DaemonCapabilities: []string{"typed-call-error-reason"}}
	for i, path := range []string{host, launcher, wheel} {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return manifest, err
		}
		data, err := readSource(absolute)
		if err != nil {
			return manifest, err
		}
		role := []ArtifactRole{ArtifactHostExecutable, ArtifactDaemonLauncher, ArtifactDaemonWheel}[i]
		source := hostSource
		if i == 2 {
			source = daemonSource
		}
		manifest.Artifacts = append(manifest.Artifacts, Artifact{role, absolute, int64(len(data)), digest(data), source})
	}
	_, err := loadBundle(manifest, "")
	return manifest, err
}
func ReadBundle(path string) (Bundle, error) {
	data, err := privatefile.ReadSource(path, 128<<10)
	if err != nil {
		return Bundle{}, err
	}
	var manifest RuntimeManifest
	if err := strictjson.Decode(data, &manifest); err != nil {
		return Bundle{}, err
	}
	return loadBundle(manifest, filepath.Dir(path))
}
func loadBundle(manifest RuntimeManifest, root string) (Bundle, error) {
	bundle := Bundle{Manifest: manifest, SHA256: objectDigest(manifest), data: map[ArtifactRole][]byte{}}
	if manifest.SchemaVersion != 1 || manifest.Platform != "windows" || manifest.Architecture != "amd64" || manifest.PythonRequires != ">=3.11,<4" || manifest.DaemonProtocol != "blender-box-v1" || len(manifest.DaemonCapabilities) != 1 || manifest.DaemonCapabilities[0] != "typed-call-error-reason" || len(manifest.Artifacts) != 3 {
		return bundle, fmt.Errorf("unsupported runtime manifest")
	}
	names := map[string]bool{}
	for _, artifact := range manifest.Artifacts {
		if artifact.Role != ArtifactHostExecutable && artifact.Role != ArtifactDaemonLauncher && artifact.Role != ArtifactDaemonWheel {
			return bundle, fmt.Errorf("unknown artifact role")
		}
		if _, exists := bundle.data[artifact.Role]; exists {
			return bundle, fmt.Errorf("duplicate artifact role")
		}
		if !regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`).MatchString(artifact.Provenance.Repository) || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(artifact.Provenance.SourceCommit) || !hex64.MatchString(string(artifact.Provenance.PatchSHA256)) || !hex64.MatchString(string(artifact.Provenance.BuildRecipeSHA256)) {
			return bundle, fmt.Errorf("invalid artifact provenance")
		}
		path := artifact.Name
		if !filepath.IsAbs(path) {
			if err := safepath.ValidateWindowsRelative("artifact", filepath.ToSlash(path)); err != nil {
				return bundle, err
			}
			path = filepath.Join(root, path)
		}
		if names[safepath.WindowsKey(path)] {
			return bundle, fmt.Errorf("duplicate artifact path")
		}
		names[safepath.WindowsKey(path)] = true
		data, err := readSource(path)
		if err != nil {
			return bundle, err
		}
		if artifact.Size < 1 || artifact.Size > maxArtifact || int64(len(data)) != artifact.Size || digest(data) != artifact.SHA256 {
			return bundle, fmt.Errorf("artifact size or SHA-256 mismatch")
		}
		if artifact.Role != ArtifactDaemonWheel {
			if err := validatePE(data); err != nil {
				return bundle, err
			}
		}
		bundle.data[artifact.Role] = data
	}
	var err error
	bundle.wheel, err = readWheel(bundle.data[ArtifactDaemonWheel])
	return bundle, err
}
func readSource(path string) ([]byte, error) {
	if err := checkPath(path, false); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	data, err := privatefile.ReadSource(path, maxArtifact)
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || int64(len(data)) != after.Size() {
		return nil, fmt.Errorf("source changed during read")
	}
	return data, nil
}
func validatePE(data []byte) error {
	file, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("runtime executable is not PE: %w", err)
	}
	defer file.Close()
	if file.Machine != pe.IMAGE_FILE_MACHINE_AMD64 || file.Characteristics&pe.IMAGE_FILE_DLL != 0 {
		return fmt.Errorf("runtime requires Windows amd64 executable")
	}
	return nil
}
func readWheel(data []byte) (map[string][]byte, error) {
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	if len(archive.File) > maxFiles {
		return nil, fmt.Errorf("wheel has excessive entries")
	}
	files := map[string][]byte{}
	names := map[string]bool{}
	var total uint64
	metadata, wheel := 0, 0
	for _, entry := range archive.File {
		name := entry.Name
		if entry.FileInfo().IsDir() {
			name = strings.TrimSuffix(name, "/")
		}
		if err := safepath.ValidateWindowsRelative("wheel entry", name); err != nil {
			return nil, err
		}
		key := safepath.WindowsKey(name)
		if names[key] {
			return nil, fmt.Errorf("wheel has duplicate or case-colliding paths")
		}
		names[key] = true
		if entry.Mode()&(os.ModeSymlink|os.ModeDevice|os.ModeNamedPipe|os.ModeSocket) != 0 {
			return nil, fmt.Errorf("wheel contains special file")
		}
		if entry.FileInfo().IsDir() {
			continue
		}
		if !entry.Mode().IsRegular() || strings.Contains(name, ".data/") || strings.HasSuffix(strings.ToLower(name), ".pth") || strings.HasSuffix(strings.ToLower(name), ".pyc") {
			return nil, fmt.Errorf("unsupported wheel file")
		}
		parts := strings.Split(name, "/")
		if len(parts) < 2 || (parts[0] != "blendersessiond" && !(strings.HasPrefix(parts[0], "blendersessiond-") && strings.HasSuffix(parts[0], ".dist-info"))) {
			return nil, fmt.Errorf("wheel has undeclared top-level package")
		}
		total += entry.UncompressedSize64
		if entry.UncompressedSize64 > maxArtifact || total > maxExpanded {
			return nil, fmt.Errorf("wheel expanded bytes exceed limit")
		}
		reader, err := entry.Open()
		if err != nil {
			return nil, err
		}
		content, readErr := io.ReadAll(io.LimitReader(reader, maxArtifact+1))
		closeErr := reader.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if len(content) > maxArtifact {
			return nil, fmt.Errorf("wheel file exceeds limit")
		}
		if strings.HasSuffix(name, ".dist-info/METADATA") {
			metadata++
			headers, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(append(content, '\n')))).ReadMIMEHeader()
			if err != nil {
				return nil, fmt.Errorf("invalid wheel metadata: %w", err)
			}
			if len(headers.Values("Name")) != 1 || headers.Get("Name") != "blendersessiond" || len(headers.Values("Requires-Python")) != 1 || headers.Get("Requires-Python") != ">=3.11" || len(headers.Values("Requires-Dist")) != 0 {
				return nil, fmt.Errorf("wheel metadata requires dependency-free blendersessiond and Python >=3.11")
			}
		}
		if strings.HasSuffix(name, ".dist-info/WHEEL") {
			wheel++
			text := string(content)
			if !strings.Contains(text, "Root-Is-Purelib: true") || !strings.Contains(text, "Tag: py3-none-any") {
				return nil, fmt.Errorf("wheel must be py3-none-any pure Python")
			}
		}
		if extension := strings.ToLower(filepath.Ext(name)); extension == ".dll" || extension == ".pyd" || extension == ".exe" || extension == ".so" {
			return nil, fmt.Errorf("pure Python wheel contains native code")
		}
		files[name] = content
	}
	for path := range files {
		for parent := filepath.ToSlash(filepath.Dir(path)); parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
			for file := range files {
				if safepath.WindowsKey(file) == safepath.WindowsKey(parent) {
					return nil, fmt.Errorf("wheel path is both file and directory")
				}
			}
		}
	}
	if metadata != 1 || wheel != 1 || files["blendersessiond/__main__.py"] == nil {
		return nil, fmt.Errorf("incomplete daemon wheel")
	}
	return files, nil
}
func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
