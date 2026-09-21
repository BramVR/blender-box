package privatefile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func Directory(root, relative string, create bool) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", fmt.Errorf("private storage root must be an absolute clean path")
	}
	if relative != "" && (filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return "", fmt.Errorf("invalid private storage path")
	}
	if create {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return "", err
		}
	}
	if err := checkDirectory(root); err != nil {
		return "", err
	}
	current := root
	if relative != "" {
		for _, component := range strings.Split(relative, string(filepath.Separator)) {
			current = filepath.Join(current, component)
			if create {
				if err := os.Mkdir(current, 0o700); err != nil && !os.IsExist(err) {
					return "", err
				}
			}
			if err := checkDirectory(current); err != nil {
				return "", err
			}
		}
	}
	if create {
		if err := syncParents(current, syncDirectory); err != nil {
			return "", err
		}
	}
	return current, nil
}

func syncParents(path string, flush func(string) error) error {
	for {
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		if err := flush(parent); err != nil {
			return err
		}
		path = parent
	}
}

func checkDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || unsafeType(info) {
		return fmt.Errorf("private storage directory is not a regular directory")
	}
	return checkPrivate(info)
}

func Read(root, relative string, limit int64) ([]byte, error) {
	parent, err := Directory(root, filepath.Dir(relative), false)
	if err != nil {
		return nil, err
	}
	return read(filepath.Join(parent, filepath.Base(relative)), limit, true)
}

func ReadDurable(root, relative string, limit int64) ([]byte, error) {
	return readDurable(root, relative, limit, syncDirectory)
}

func readDurable(root, relative string, limit int64, flush func(string) error) ([]byte, error) {
	data, err := Read(root, relative, limit)
	if err != nil {
		return nil, err
	}
	if err := syncParents(filepath.Join(root, relative), flush); err != nil {
		return nil, err
	}
	return data, nil
}

func ReadSource(path string, limit int64) ([]byte, error) { return read(path, limit, false) }

func read(path string, limit int64, private bool) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || unsafeType(before) || before.Size() > limit {
		return nil, fmt.Errorf("file must be bounded and regular")
	}
	if private {
		if err := checkPrivate(before); err != nil {
			return nil, err
		}
	}
	file, err := openRead(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || unsafeType(opened) {
		return nil, fmt.Errorf("opened file is not regular")
	}
	if private {
		if err := checkPrivate(opened); err != nil {
			return nil, err
		}
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds size limit")
	}
	return data, nil
}

func Publish(root, relative string, contents []byte, replace bool) error {
	if len(contents) > 64<<10 {
		return fmt.Errorf("private record exceeds size limit")
	}
	parent, err := Directory(root, filepath.Dir(relative), true)
	if err != nil {
		return err
	}
	destination := filepath.Join(parent, filepath.Base(relative))
	if info, err := os.Lstat(destination); err == nil {
		if !info.Mode().IsRegular() || unsafeType(info) {
			return fmt.Errorf("destination is not a regular file")
		}
		if err := checkPrivate(info); err != nil {
			return err
		}
		if !replace {
			return os.ErrExist
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	temporary, err := os.CreateTemp(parent, ".pending-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := publish(name, destination, replace); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func Remove(root, relative string, limit int64) error {
	if _, err := Read(root, relative, limit); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(root, relative)); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(filepath.Join(root, relative)))
}
