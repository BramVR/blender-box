package target

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BramVR/blender-box/internal/privatefile"
)

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
var reservedName = regexp.MustCompile(`^(con|prn|aux|nul|com[1-9]|lpt[1-9])$`)

func ValidateName(name string) error {
	if !namePattern.MatchString(name) || reservedName.MatchString(name) {
		return fmt.Errorf("invalid target name")
	}
	return nil
}
func ConfigDir() (string, error) {
	if root, present := os.LookupEnv("BLENDER_BOX_CONFIG_DIR"); present {
		if !filepath.IsAbs(root) {
			return "", fmt.Errorf("BLENDER_BOX_CONFIG_DIR must be absolute")
		}
		return filepath.Clean(root), nil
	}
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "blender-box"), nil
}

type Store struct{ Root string }
type Entry struct {
	Name     string `json:"name"`
	Platform string `json:"platform"`
}

func profilePath(name string) string { return filepath.Join("targets", name+".json") }
func (store Store) Import(name, source string, replace bool) (Target, error) {
	if err := ValidateName(name); err != nil {
		return Target{}, err
	}
	selected, err := Load(source)
	if err != nil {
		return Target{}, err
	}
	encoded, err := json.Marshal(selected)
	if err != nil {
		return Target{}, err
	}
	if err := privatefile.Publish(store.Root, profilePath(name), append(encoded, '\n'), replace); err != nil {
		if os.IsExist(err) {
			return Target{}, fmt.Errorf("target name already exists; use --replace")
		}
		return Target{}, fmt.Errorf("import target: %w", err)
	}
	return selected, nil
}
func (store Store) Show(name string) (Target, error) {
	if err := ValidateName(name); err != nil {
		return Target{}, err
	}
	content, err := privatefile.Read(store.Root, profilePath(name), MaxDocumentSize)
	if err != nil {
		return Target{}, fmt.Errorf("read saved target: %w", err)
	}
	return Decode(content)
}
func (store Store) Resolve(name string) (Target, error) { return store.Show(name) }
func (store Store) List() ([]Entry, error) {
	entries := []Entry{}
	directory, err := privatefile.Directory(store.Root, "targets", false)
	if os.IsNotExist(err) {
		return entries, nil
	}
	if err != nil {
		return nil, err
	}
	files, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name(), ".pending-") {
			continue
		}
		if !strings.HasSuffix(file.Name(), ".json") {
			return nil, fmt.Errorf("unexpected saved target entry")
		}
		name := strings.TrimSuffix(file.Name(), ".json")
		selected, err := store.Show(name)
		if err != nil {
			return nil, err
		}
		entries = append(entries, Entry{Name: name, Platform: selected.Platform()})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}
func (store Store) Forget(name string) (Target, error) {
	selected, err := store.Show(name)
	if err != nil {
		return Target{}, err
	}
	if err := privatefile.Remove(store.Root, profilePath(name), MaxDocumentSize); err != nil {
		return Target{}, err
	}
	return selected, nil
}
