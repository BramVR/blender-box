package windowsinstall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/strictjson"
)

func checkPath(path string, missing bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("path must be absolute and clean")
	}
	current := path
	for {
		info, err := os.Lstat(current)
		if err != nil {
			if !os.IsNotExist(err) || !missing {
				return err
			}
		} else if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return fmt.Errorf("path contains reparse or irregular entry")
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return nil
}
func observeFile(path string, planned File) (File, error) {
	if err := checkPath(path, false); err != nil {
		return File{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return File{}, err
	}
	result := planned
	if planned.Kind == "directory" {
		if !info.IsDir() {
			return File{}, fmt.Errorf("owned directory changed type")
		}
	} else {
		if !info.Mode().IsRegular() {
			return File{}, fmt.Errorf("owned file changed type")
		}
		data, err := privatefile.ReadSource(path, maxArtifact)
		if err != nil {
			return File{}, err
		}
		if int64(len(data)) != planned.Size || digest(data) != planned.SHA256 {
			return File{}, fmt.Errorf("owned file changed bytes: %s", planned.Path)
		}
	}
	result.Identity, err = fileIdentity(path)
	if err != nil {
		return File{}, err
	}
	if planned.Identity != "" && result.Identity != planned.Identity {
		return File{}, fmt.Errorf("owned file identity changed: %s", planned.Path)
	}
	return result, nil
}
func publishBytes(path string, data []byte, replace bool) error {
	if err := checkPath(filepath.Dir(path), false); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !replace || !info.Mode().IsRegular() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return fmt.Errorf("publication collision")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".install-pending-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = publishFile(name, path, replace); err != nil {
		return err
	}
	got, err := privatefile.ReadSource(path, int64(len(data)))
	if err != nil {
		return err
	}
	if !bytes.Equal(data, got) {
		return fmt.Errorf("published bytes failed readback")
	}
	return nil
}
func saveReceipt(path string, receipt *installationReceipt, replace bool) error {
	next := *receipt
	next.Generation++
	if err := next.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if len(data) > 2<<20 {
		return fmt.Errorf("receipt exceeds limit")
	}
	if err := publishBytes(path, data, replace); err != nil {
		return err
	}
	*receipt = next
	return nil
}
func readReceipt(path string) (installationReceipt, error) {
	var receipt installationReceipt
	data, err := privatefile.ReadSource(path, 2<<20)
	if err != nil {
		return receipt, err
	}
	err = strictjson.Decode(data, &receipt)
	if err == nil {
		err = receipt.validate()
	}
	return receipt, err
}
