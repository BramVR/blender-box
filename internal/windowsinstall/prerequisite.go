package windowsinstall

import (
	"crypto/sha256"
	"debug/pe"
	"fmt"
	"io"
	"os"
)

const maxPrerequisite = 2 << 30

func hashPrerequisite(path string, executable bool) (SHA256, string, error) {
	if err := checkPath(path, false); err != nil {
		return "", "", err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return "", "", err
	}
	if !before.Mode().IsRegular() || before.Size() > maxPrerequisite {
		return "", "", fmt.Errorf("prerequisite must be a regular file at most 2 GiB")
	}
	identity, err := fileIdentity(path)
	if err != nil {
		return "", "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return "", "", err
	}
	if !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		return "", "", fmt.Errorf("prerequisite changed before read")
	}
	if executable {
		image, err := pe.NewFile(file)
		if err != nil {
			return "", "", fmt.Errorf("prerequisite is not PE: %w", err)
		}
		defer image.Close()
		if image.Machine != pe.IMAGE_FILE_MACHINE_AMD64 || image.Characteristics&pe.IMAGE_FILE_DLL != 0 {
			return "", "", fmt.Errorf("prerequisite requires Windows amd64 executable")
		}
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, maxPrerequisite+1))
	if err != nil {
		return "", "", err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return "", "", err
	}
	afterIdentity, err := fileIdentity(path)
	if err != nil {
		return "", "", err
	}
	if size > maxPrerequisite || size != before.Size() || size != after.Size() || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || identity != afterIdentity {
		return "", "", fmt.Errorf("prerequisite changed during read")
	}
	return SHA256(fmt.Sprintf("%x", hash.Sum(nil))), identity, nil
}
