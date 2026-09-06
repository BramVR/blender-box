package linuxruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/BramVR/blender-box/internal/linuxtarget"
)

//go:embed reviewed-daemon-manifest.json
var provenance []byte

func CleanEnvironment(extra map[string]string) []string {
	values := map[string]string{"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1", "PYTHONDONTWRITEBYTECODE": "1"}
	for key, value := range extra {
		if strings.HasPrefix(key, "BLENDER_") || key == "BLENDERSESSIOND_STATE_DIR" || key == "HOME" || key == "DISPLAY" || key == "XAUTHORITY" || key == "XDG_RUNTIME_DIR" || key == "DBUS_SESSION_BUS_ADDRESS" {
			values[key] = value
		}
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result
}

func Run(ctx context.Context, selected linuxtarget.DaemonRuntime, args []string, environment map[string]string) ([]byte, error) {
	if err := Verify(ctx, selected); err != nil {
		return nil, err
	}
	return execute(ctx, selected.PythonExecutable, append([]string{"-I", "-B", "-m", "blendersessiond"}, args...), CleanEnvironment(environment))
}
func Verify(ctx context.Context, selected linuxtarget.DaemonRuntime) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("reviewed daemon runtime requires native Linux")
	}
	if err := selected.Validate(); err != nil {
		return err
	}
	if err := verifyTree(selected, uint32(os.Getuid())); err != nil {
		return fmt.Errorf("reviewed daemon runtime unavailable: %w; externally provision the corrected copied CPython 3.12 venv", err)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := execute(probeCtx, selected.PythonExecutable, []string{"-I", "-B", "-c", `import importlib.util,json,sys;print(json.dumps({"version":list(sys.version_info[:2]),"prefix":sys.prefix,"base_prefix":sys.base_prefix,"origin":importlib.util.find_spec("blendersessiond").origin,"path":sys.path}))`}, CleanEnvironment(nil))
	if err != nil {
		return fmt.Errorf("daemon import-origin probe: %w", err)
	}
	var result struct {
		Version    []int    `json:"version"`
		Prefix     string   `json:"prefix"`
		BasePrefix string   `json:"base_prefix"`
		Origin     string   `json:"origin"`
		Path       []string `json:"path"`
	}
	if json.Unmarshal(output, &result) != nil || len(result.Version) != 2 || result.Version[0] != 3 || result.Version[1] != 12 || result.Prefix != selected.VenvRoot || result.BasePrefix != "/usr" || result.Origin != selected.VenvRoot+"/lib/python3.12/site-packages/blendersessiond/__init__.py" {
		return fmt.Errorf("daemon interpreter prefix or import origin does not match reviewed runtime")
	}
	allowed := map[string]bool{"/usr/lib/python312.zip": true, "/usr/lib/python3.12": true, "/usr/lib/python3.12/lib-dynload": true, selected.VenvRoot + "/lib/python3.12/site-packages": true}
	for _, path := range result.Path {
		if !allowed[path] {
			return fmt.Errorf("unexpected daemon import path %q", path)
		}
	}
	return nil
}
func verifyTree(selected linuxtarget.DaemonRuntime, uid uint32) error {
	if err := SafePath(selected.VenvRoot, uid, true); err != nil {
		return err
	}
	if err := SafePath(selected.VenvRoot+"/pyvenv.cfg", uid, false); err != nil {
		return err
	}
	cfg, err := readBounded(selected.VenvRoot+"/pyvenv.cfg", 4096)
	if err != nil {
		return err
	}
	settings := map[string]string{}
	for _, line := range strings.Split(string(cfg), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("invalid pyvenv.cfg")
		}
		key = strings.TrimSpace(key)
		if _, exists := settings[key]; exists {
			return fmt.Errorf("duplicate pyvenv.cfg key")
		}
		settings[key] = strings.TrimSpace(value)
	}
	if settings["include-system-site-packages"] != "false" || settings["home"] != "/usr/bin" || !strings.HasPrefix(settings["version"], "3.12.") || settings["executable"] != "/usr/bin/python3.12" {
		return fmt.Errorf("venv must use copied system CPython 3.12 without system site packages")
	}
	if err := SafePath("/usr/bin/python3.12", 0, false); err != nil {
		return err
	}
	systemPython, err := fileHash("/usr/bin/python3.12", 64<<20)
	if err != nil {
		return err
	}
	var manifest struct {
		Files map[string]string `json:"package_files"`
	}
	if json.Unmarshal(provenance, &manifest) != nil || len(manifest.Files) != 20 {
		return fmt.Errorf("invalid compiled provenance manifest")
	}
	return verifyContents(selected, uid, systemPython, manifest.Files)
}
func verifyContents(selected linuxtarget.DaemonRuntime, uid uint32, systemPython string, hashes map[string]string) error {
	seen := map[string]bool{}
	site := selected.VenvRoot + "/lib/python3.12/site-packages"
	packageRoot := site + "/blendersessiond"
	entries, metadataDirs := 0, 0
	err := walkBounded(selected.VenvRoot, 64, func(name string, entry os.DirEntry) error {
		entries++
		if entries > 64 {
			return fmt.Errorf("runtime tree exceeds entry bound")
		}
		if err := SafePath(name, uid, name == selected.VenvRoot); err != nil {
			return err
		}
		rel, _ := filepath.Rel(selected.VenvRoot, name)
		if entry.IsDir() {
			if filepath.Dir(name) == site && strings.HasSuffix(entry.Name(), ".dist-info") {
				metadataDirs++
				if metadataDirs > 1 {
					return fmt.Errorf("runtime permits at most one daemon metadata directory")
				}
			}
			if rel == "." || rel == "bin" || rel == "include" || rel == "lib" || rel == "lib/python3.12" || name == site || name == packageRoot || name == packageRoot+"/vendor" || (filepath.Dir(name) == site && strings.HasPrefix(entry.Name(), "blendersessiond-") && strings.HasSuffix(entry.Name(), ".dist-info")) {
				return nil
			}
			return fmt.Errorf("unexpected runtime directory %q", rel)
		}
		if strings.HasPrefix(name, packageRoot+"/") {
			file := strings.TrimPrefix(name, packageRoot+"/")
			want, ok := hashes[file]
			if !ok {
				return fmt.Errorf("unreviewed daemon file %q", file)
			}
			got, err := fileHash(name, 4<<20)
			if err != nil {
				return err
			}
			if got != want {
				return fmt.Errorf("reviewed daemon hash mismatch for %s", file)
			}
			seen[file] = true
			return nil
		}
		if rel == "pyvenv.cfg" {
			return nil
		}
		if rel == "bin/python" || rel == "bin/python3" || rel == "bin/python3.12" {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if info.Mode().Perm()&0111 == 0 {
				return fmt.Errorf("runtime Python is not executable")
			}
			got, err := fileHash(name, 64<<20)
			if err != nil {
				return err
			}
			if got != systemPython {
				return fmt.Errorf("runtime interpreter is not a copy of system CPython")
			}
			return nil
		}
		parent := filepath.Base(filepath.Dir(name))
		if filepath.Dir(filepath.Dir(name)) == site && strings.HasPrefix(parent, "blendersessiond-") && strings.HasSuffix(parent, ".dist-info") {
			switch entry.Name() {
			case "METADATA", "WHEEL", "RECORD", "INSTALLER", "REQUESTED", "direct_url.json", "entry_points.txt", "top_level.txt":
				_, err := readBounded(name, 256<<10)
				return err
			}
		}
		return fmt.Errorf("unexpected runtime file %q; packages, .pth, customization and bytecode are forbidden", rel)
	})
	if err != nil {
		return err
	}
	if len(seen) != len(hashes) {
		return fmt.Errorf("reviewed daemon package is incomplete")
	}
	if _, err := os.Lstat(selected.PythonExecutable); err != nil {
		return err
	}
	return nil
}
func readBounded(name string, limit int64) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("unsafe or oversized file %s", name)
	}
	value, err := io.ReadAll(io.LimitReader(file, limit+1))
	if int64(len(value)) > limit {
		return nil, fmt.Errorf("oversized file %s", name)
	}
	return value, err
}
func fileHash(name string, limit int64) (string, error) {
	value, err := readBounded(name, limit)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:]), nil
}

type boundedOutput struct {
	bytes.Buffer
	exceeded bool
	limit    int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - b.Len()
	if len(p) > remaining {
		b.exceeded = true
		p = p[:remaining]
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}
func execute(ctx context.Context, executable string, args, environment []string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, args...)
	command.Env = environment
	stdout := &boundedOutput{limit: 4 << 20}
	stderr := &boundedOutput{limit: 64 << 10}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if stdout.exceeded || stderr.exceeded {
		return nil, fmt.Errorf("Linux process output exceeds limit")
	}
	if err != nil {
		return stdout.Bytes(), fmt.Errorf("Linux process failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func walkBounded(root string, limit int, visit func(string, os.DirEntry) error) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	remaining := limit
	var walk func(string, os.DirEntry) error
	walk = func(name string, entry os.DirEntry) error {
		remaining--
		if remaining < 0 {
			return fmt.Errorf("filesystem tree exceeds entry bound")
		}
		if err := visit(name, entry); err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		directory, err := os.Open(name)
		if err != nil {
			return err
		}
		entries, readErr := directory.ReadDir(remaining + 1)
		closeErr := directory.Close()
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if len(entries) > remaining {
			return fmt.Errorf("filesystem tree exceeds entry bound")
		}
		for _, child := range entries {
			if err := walk(filepath.Join(name, child.Name()), child); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root, fs.FileInfoToDirEntry(info))
}
