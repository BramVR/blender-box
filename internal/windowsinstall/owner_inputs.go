package windowsinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/BramVR/blender-box/internal/safepath"
)

func pinExecutionInputs(ctx context.Context, request Request, inspection Inspection) (File, []File, func(), error) {
	var opened []*os.File
	release := func() {
		for _, file := range opened {
			_ = file.Close()
		}
	}
	pin := func(path string, limit int64) (File, error) {
		if err := ctx.Err(); err != nil {
			return File{}, err
		}
		if err := checkPath(path, false); err != nil {
			return File{}, err
		}
		file, err := openPinnedSource(path)
		if err != nil {
			return File{}, err
		}
		opened = append(opened, file)
		hash := sha256.New()
		size, err := io.Copy(hash, io.LimitReader(file, limit+1))
		if err != nil {
			return File{}, err
		}
		if size > limit {
			return File{}, fmt.Errorf("input exceeds limit")
		}
		identity, err := fileIdentity(path)
		if err != nil {
			return File{}, err
		}
		return File{Path: path, Kind: "file", Size: size, SHA256: SHA256(hex.EncodeToString(hash.Sum(nil))), Identity: identity}, nil
	}
	fail := func(err error) (File, []File, func(), error) { release(); return File{}, nil, func() {}, err }
	executable, err := os.Executable()
	if err != nil {
		return fail(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return fail(err)
	}
	root := safepath.WindowsKey(filepath.Join(request.StateRoot, "installations", string(request.InstallationID))) + string(filepath.Separator)
	if strings.HasPrefix(safepath.WindowsKey(executable), root) {
		return fail(fmt.Errorf("setup keeper requires a bootstrap outside the selected installation"))
	}
	bootstrap, err := pin(executable, maxArtifact)
	if err != nil {
		return fail(err)
	}
	inputs := []File{}
	if request.Operation == "install" {
		bundle, err := ReadBundle(request.RuntimePath)
		if err != nil {
			return fail(err)
		}
		paths := []string{request.RuntimePath, request.BlenderPath, request.PythonPath}
		for _, artifact := range bundle.Manifest.Artifacts {
			paths = append(paths, artifact.Name)
		}
		if inspection.Python == nil {
			return fail(fmt.Errorf("Python prerequisite missing"))
		}
		for _, candidate := range []Candidate{inspection.Python.Template, inspection.Python.DLL, inspection.Python.VenvSource} {
			paths = append(paths, candidate.Path)
		}
		seen := map[string]bool{}
		for _, path := range paths {
			if seen[path] {
				continue
			}
			seen[path] = true
			limit := int64(2 << 30)
			if path == request.RuntimePath {
				limit = 2 << 20
			}
			for _, artifact := range bundle.Manifest.Artifacts {
				if path == artifact.Name {
					limit = maxArtifact
				}
			}
			file, err := pin(path, limit)
			if err != nil {
				return fail(err)
			}
			inputs = append(inputs, file)
		}
	}
	return bootstrap, inputs, release, nil
}

func verifyExecutionInput(expected File) error {
	if err := checkPath(expected.Path, false); err != nil {
		return err
	}
	file, err := openPinnedSource(expected.Path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if expected.Size < 0 || expected.Size > 2<<30 {
		return fmt.Errorf("input size exceeds limit")
	}
	size, err := io.Copy(hash, io.LimitReader(file, expected.Size+1))
	if err != nil {
		return err
	}
	identity, err := fileIdentity(expected.Path)
	if err != nil {
		return err
	}
	if size != expected.Size || SHA256(hex.EncodeToString(hash.Sum(nil))) != expected.SHA256 || identity != expected.Identity {
		return fmt.Errorf("execution input changed")
	}
	return nil
}
