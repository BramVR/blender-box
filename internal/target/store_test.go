package target

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/BramVR/blender-box/internal/windowstarget"
)

func fixtureTarget(t *testing.T) Target {
	t.Helper()
	value, err := NewWindows("windows-test", windowstarget.Config{SSHUser: "test-user", InteractiveUser: "test-user", WorkRoot: `C:\BlenderBoxTest`, TaskName: "BlenderBoxTest", BlenderExecutable: `C:\Apps\blender.exe`, SessionBrokerExecutable: `C:\BlenderBoxTest\bin\daemon.exe`, HostExecutable: `C:\BlenderBoxTest\bin\host.exe`})
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func sourceTarget(t *testing.T, value Target) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestVersionsNormalizeAndFingerprintEveryField(t *testing.T) {
	original := fixtureTarget(t)
	flat := struct {
		SchemaVersion int    `json:"schema_version"`
		SSHAlias      string `json:"ssh_alias"`
		windowstarget.Config
	}{1, original.SSHAlias(), original.Windows()}
	legacy, _ := json.Marshal(flat)
	v1, err := Decode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	v2bytes, _ := json.Marshal(original)
	v2, err := Decode(v2bytes)
	if err != nil {
		t.Fatal(err)
	}
	if v1 != v2 || v1.Fingerprint() != original.Fingerprint() {
		t.Fatal("versions do not normalize identically")
	}
	if string(v2bytes) == string(legacy) {
		t.Fatal("encoding did not upgrade document")
	}
	for _, field := range []string{"SSHUser", "InteractiveUser", "WorkRoot", "TaskName", "BlenderExecutable", "SessionBrokerExecutable", "HostExecutable"} {
		t.Run(field, func(t *testing.T) {
			config := original.Windows()
			value := reflect.ValueOf(&config).Elem().FieldByName(field)
			if field == "WorkRoot" {
				config.WorkRoot = `C:\OtherRoot`
				config.SessionBrokerExecutable = config.WorkRoot + `\bin\daemon.exe`
				config.HostExecutable = config.WorkRoot + `\bin\host.exe`
			} else {
				value.SetString(value.String() + "-changed")
			}
			changed, err := NewWindows(original.SSHAlias(), config)
			if err != nil {
				t.Fatal(err)
			}
			if changed.Fingerprint() == original.Fingerprint() {
				t.Fatal("field absent from fingerprint")
			}
		})
	}
	changed, err := NewWindows("other-alias", original.Windows())
	if err != nil {
		t.Fatal(err)
	}
	if changed.Fingerprint() == original.Fingerprint() {
		t.Fatal("alias absent from fingerprint")
	}
	config := original.Windows()
	config.SSHUser = strings.ToUpper(config.SSHUser)
	changed, err = NewWindows(original.SSHAlias(), config)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Fingerprint() == original.Fingerprint() {
		t.Fatal("target strings were case-folded")
	}
}
func TestDecodeRejectsAmbiguousAndUnsupportedDocuments(t *testing.T) {
	data, _ := json.Marshal(fixtureTarget(t))
	valid := string(data)
	tests := map[string]string{
		"unknown version":        strings.Replace(valid, `"schema_version":2`, `"schema_version":3`, 1),
		"unknown platform":       strings.Replace(valid, `"platform":"windows"`, `"platform":"linux"`, 1),
		"null body":              strings.Replace(valid, `"windows":{`, `"windows":null,"extra":{`, 1),
		"extra field":            strings.Replace(valid, `"windows":{`, `"linux":{},"windows":{`, 1),
		"nested unknown":         strings.Replace(valid, `"windows":{`, `"windows":{"extra":true,`, 1),
		"duplicate version":      strings.Replace(valid, `"schema_version":2`, `"schema_version":1,"schema_version":2`, 1),
		"duplicate nested":       strings.Replace(valid, `"ssh_user":"test-user"`, `"ssh_user":"other","ssh_user":"test-user"`, 1),
		"duplicate escaped":      strings.Replace(valid, `"ssh_user":"test-user"`, `"ssh_user":"other","ssh_\u0075ser":"test-user"`, 1),
		"case variant duplicate": strings.Replace(valid, `"ssh_alias":"windows-test"`, `"ssh_alias":"windows-test","SSH_ALIAS":"changed"`, 1),
		"uppercase field":        strings.Replace(valid, `"work_root"`, `"WORK_ROOT"`, 1),
		"unicode fold alias":     strings.Replace(valid, `"schema_version"`, `"ſchema_version"`, 1),
		"trailing":               valid + `{}`,
		"oversized":              strings.Repeat(" ", MaxDocumentSize) + valid,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(input)); err == nil {
				t.Fatal("invalid document accepted")
			}
		})
	}
	if err := (Target{}).Validate(); err == nil {
		t.Fatal("zero target accepted")
	}
}
func TestStoreCopyReplaceForgetAndReadOnly(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	store := Store{Root: root}
	list, err := store.List()
	if err != nil || len(list) != 0 {
		t.Fatalf("empty list %v %v", list, err)
	}
	if _, err := store.Show("missing"); err == nil {
		t.Fatal("missing profile accepted")
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("reads created storage")
	}
	original := fixtureTarget(t)
	source := sourceTarget(t, original)
	if _, err := store.Import("studio", source, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved, err := store.Resolve("studio")
	if err != nil || saved != original {
		t.Fatalf("source mutation changed copy %v", err)
	}
	source = sourceTarget(t, original)
	if _, err := store.Import("studio", source, false); err == nil {
		t.Fatal("implicit replace")
	}
	changed, _ := NewWindows("different", original.Windows())
	changedSource := sourceTarget(t, changed)
	if _, err := store.Import("studio", changedSource, true); err != nil {
		t.Fatal(err)
	}
	if saved, err := store.Show("studio"); err != nil || saved != changed {
		t.Fatal("explicit replacement not saved")
	}
	if _, err := store.Import("another", source, false); err != nil {
		t.Fatal(err)
	}
	list, err = store.List()
	if err != nil || len(list) != 2 || list[0].Name != "another" || list[1].Name != "studio" {
		t.Fatalf("list=%v %v", list, err)
	}
	journalDir := filepath.Join(root, "runs")
	if err := os.Mkdir(journalDir, 0o700); err != nil {
		t.Fatal(err)
	}
	journalFile := filepath.Join(journalDir, "original.json")
	if err := os.WriteFile(journalFile, []byte("authority"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Forget("studio"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Show("studio"); err == nil {
		t.Fatal("forgotten target resolved")
	}
	if data, err := os.ReadFile(journalFile); err != nil || string(data) != "authority" {
		t.Fatal("forget touched authority")
	}
}
func TestStorePortableNames(t *testing.T) {
	for _, name := range []string{"", "Studio", "../a", "a/b", "a\\b", "con", "nul", "com1", "lpt9", "a.json", "1studio", strings.Repeat("a", 64)} {
		if err := ValidateName(name); err == nil {
			t.Fatalf("accepted name %q", name)
		}
	}
	for _, name := range []string{"studio", "a", "studio-2", "studio_a", strings.Repeat("a", 63)} {
		if err := ValidateName(name); err != nil {
			t.Fatalf("name %q: %v", name, err)
		}
	}
}
func TestConcurrentImportPublishesOneCompleteWinner(t *testing.T) {
	store := Store{Root: filepath.Join(t.TempDir(), "private")}
	original := fixtureTarget(t)
	source := sourceTarget(t, original)
	const workers = 16
	results := make(chan error, workers)
	var group sync.WaitGroup
	for i := 0; i < workers; i++ {
		group.Add(1)
		go func() { defer group.Done(); _, err := store.Import("studio", source, false); results <- err }()
	}
	group.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("exclusive publication winners=%d", winners)
	}
	if saved, err := store.Show("studio"); err != nil || saved != original {
		t.Fatalf("partial winner: %v", err)
	}
	var outputs sync.WaitGroup
	for i := 0; i < workers; i++ {
		outputs.Add(1)
		go func() {
			defer outputs.Done()
			if _, err := store.Import("studio", source, true); err != nil {
				t.Error(err)
			}
			if saved, err := store.Show("studio"); err != nil || saved != original {
				t.Errorf("partial replace: %v", err)
			}
		}()
	}
	outputs.Wait()
}
func TestImportFailurePreservesExistingProfileAndSource(t *testing.T) {
	store := Store{Root: filepath.Join(t.TempDir(), "private")}
	source := sourceTarget(t, fixtureTarget(t))
	before, _ := os.ReadFile(source)
	if _, err := store.Import("studio", source, false); err != nil {
		t.Fatal(err)
	}
	corrupt := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(corrupt, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import("studio", corrupt, true); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	if saved, err := store.Show("studio"); err != nil || saved != fixtureTarget(t) {
		t.Fatal("failed replacement changed profile")
	}
	after, _ := os.ReadFile(source)
	if !bytes.Equal(before, after) {
		t.Fatal("import rewrote source")
	}
}
func TestConfigDirOverride(t *testing.T) {
	t.Setenv("BLENDER_BOX_CONFIG_DIR", "relative")
	if _, err := ConfigDir(); err == nil {
		t.Fatal("relative override accepted")
	}
	t.Setenv("BLENDER_BOX_CONFIG_DIR", filepath.Join(t.TempDir(), "private"))
	root, err := ConfigDir()
	if err != nil || root != os.Getenv("BLENDER_BOX_CONFIG_DIR") {
		t.Fatalf("config root: %q %v", root, err)
	}
}

func TestLegacyDecodeRejectsCaseAliases(t *testing.T) {
	value := fixtureTarget(t)
	flat := struct {
		SchemaVersion int    `json:"schema_version"`
		SSHAlias      string `json:"ssh_alias"`
		windowstarget.Config
	}{1, value.SSHAlias(), value.Windows()}
	data, _ := json.Marshal(flat)
	for _, input := range []string{
		strings.Replace(string(data), `"ssh_alias":"windows-test"`, `"ssh_alias":"windows-test","SSH_ALIAS":"replacement"`, 1),
		strings.Replace(string(data), `"work_root"`, `"WORK_ROOT"`, 1),
	} {
		if _, err := Decode([]byte(input)); err == nil {
			t.Fatal("legacy case alias accepted")
		}
	}
}
