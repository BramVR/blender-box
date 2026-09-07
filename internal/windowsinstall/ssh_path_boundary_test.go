package windowsinstall

import (
	"context"
	"fmt"
	"io/fs"
	"reflect"
	"testing"
	"testing/fstest"
)

func TestSSHProductionPathGrammarRefusesBeforeInspection(t *testing.T) {
	_, _, r := sshPreviewFixture(t)
	for _, path := range []string{"/fixture/root", `\\server\share\root`, `\\?\C:\root`, `\\.\C:\root`, `C:\root:stream`, `C:/root`, `C:\NUL\root`, `C:\root\..\other`, `C:\root.`, `C:\root\`} {
		t.Run(path, func(t *testing.T) {
			r.StateRoot = path
			if err := validateSSHRequest(r); err == nil {
				t.Fatal("production request accepted noncanonical local Windows path")
			}
			result, err := PreviewSSH(context.Background(), r)
			if err == nil || len(result.Problems) != 1 || result.Problems[0].Code != "invalid-request" {
				t.Fatalf("request reached observation: %+v %v", result, err)
			}
		})
	}
}

type sshOrderFile struct {
	sshHeldFile
	info   fs.FileInfo
	name   string
	events *[]string
	list   func(int) ([]fs.DirEntry, error)
}

func (f *sshOrderFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *sshOrderFile) Close() error               { *f.events = append(*f.events, "close "+f.name); return nil }

type sshOrderBackend struct {
	events    []string
	rootErr   error
	bad       string
	directory fs.FileInfo
	reparse   fs.FileInfo
	entries   []fs.DirEntry
}

func (b *sshOrderBackend) anchor(path string) (sshHeldFile, error) {
	b.events = append(b.events, "anchor "+path)
	if b.rootErr != nil {
		return nil, b.rootErr
	}
	return &sshOrderFile{info: b.directory, name: path, events: &b.events}, nil
}
func (b *sshOrderBackend) child(parent sshHeldFile, name string) (sshHeldFile, error) {
	b.events = append(b.events, "child "+name)
	info := b.directory
	if name == b.bad {
		info = b.reparse
	}
	return &sshOrderFile{info: info, name: name, events: &b.events, list: func(maximum int) ([]fs.DirEntry, error) {
		b.events = append(b.events, "list "+name)
		return append([]fs.DirEntry(nil), b.entries...), nil
	}}, nil
}
func TestSSHScopeRejectsBeforeDescendantOpen(t *testing.T) {
	entries := fstest.MapFS{"directory": {Mode: fs.ModeDir | 0700}, "link": {Mode: fs.ModeSymlink | 0700}}
	directory, _ := entries.Stat("directory")
	reparse := sshModeInfo{directory, fs.ModeSymlink | 0700}
	for _, bad := range []string{`\\server\share\leaf`, `\\?\C:\leaf`, `C:\name:stream`, `C:/leaf`, `C:\NUL\leaf`} {
		backend := &sshOrderBackend{directory: directory, reparse: reparse}
		scope := newSSHReadScope(backend)
		if _, err := scope.Stat(bad); err == nil {
			t.Fatal("invalid path accepted")
		}
		scope.Close()
		if len(backend.events) != 0 {
			t.Fatalf("invalid path performed I/O: %v", backend.events)
		}
	}
	backend := &sshOrderBackend{directory: directory, reparse: reparse, bad: "junction"}
	scope := newSSHReadScope(backend)
	if _, err := scope.Stat(`C:\safe\junction\missing`); err == nil {
		t.Fatal("reparse ancestor accepted")
	}
	if want := []string{`anchor C:\`, "child safe", "child junction", "close junction"}; !reflect.DeepEqual(backend.events, want) {
		t.Fatalf("descendant touched or wrong lifetime: %v", backend.events)
	}
	scope.Close()
	if want := []string{`anchor C:\`, "child safe", "child junction", "close junction", "close safe", `close C:\`}; !reflect.DeepEqual(backend.events, want) {
		t.Fatalf("handles leaked: %v", backend.events)
	}
	backend = &sshOrderBackend{rootErr: fmt.Errorf("non-fixed captured volume")}
	scope = newSSHReadScope(backend)
	if _, err := scope.Stat(`C:\leaf`); err == nil {
		t.Fatal("non-fixed volume accepted")
	}
	scope.Close()
	if len(backend.events) != 1 {
		t.Fatalf("descendants opened before fixed-volume acceptance: %v", backend.events)
	}
}

func TestSSHPhysicalVolumeSpelling(t *testing.T) {
	if !sshPhysicalVolume(`\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\`) {
		t.Fatal("captured Windows volume rejected")
	}
	for _, path := range []string{`C:\`, `\\server\share\`, `\\?\C:\`, `\\?\Volume{not-a-guid}\`, `\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\child`} {
		if sshPhysicalVolume(path) {
			t.Fatalf("non-volume anchor accepted: %s", path)
		}
	}
}

type sshModeInfo struct {
	fs.FileInfo
	mode fs.FileMode
}

func (s sshModeInfo) Mode() fs.FileMode { return s.mode }

type sshFakeVolume struct {
	events   []string
	physical string
	local    bool
}

func (v *sshFakeVolume) capture(root string) (string, error) {
	v.events = append(v.events, "capture "+root)
	return v.physical, nil
}
func (v *sshFakeVolume) fixed(path string) bool {
	v.events = append(v.events, "classify "+path)
	return v.local
}
func (v *sshFakeVolume) openVolume(path string) (sshHeldFile, error) {
	v.events = append(v.events, "open "+path)
	return nil, nil
}
func TestSSHAnchorClassifiesCapturedVolumeBeforeOpen(t *testing.T) {
	const physical = `\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\`
	for _, local := range []bool{false, true} {
		volume := &sshFakeVolume{physical: physical, local: local}
		_, err := sshCaptureAnchor(`C:\`, volume)
		if (err == nil) != local {
			t.Fatalf("classification result: %v", err)
		}
		want := []string{`capture C:\`, "classify " + physical}
		if local {
			want = append(want, "open "+physical)
		}
		if !reflect.DeepEqual(volume.events, want) {
			t.Fatalf("classified or opened mutable drive alias: %v", volume.events)
		}
	}
	volume := &sshFakeVolume{physical: `\\server\share\`}
	if _, err := sshCaptureAnchor(`C:\`, volume); err == nil || len(volume.events) != 1 {
		t.Fatalf("untrusted capture reached classification: %v", volume.events)
	}
	volume = &sshFakeVolume{}
	if _, err := sshCaptureAnchor(`\\server\share\`, volume); err == nil || len(volume.events) != 0 {
		t.Fatalf("invalid drive reached I/O: %v", volume.events)
	}
}

func (f *sshOrderFile) ReadDir(maximum int) ([]fs.DirEntry, error) { return f.list(maximum) }

type sshNameInfo struct {
	fs.FileInfo
	name string
}

func (n sshNameInfo) Name() string { return n.name }
func TestSSHScopeReenumeratesAndRefusesNewReparseEntry(t *testing.T) {
	entries := fstest.MapFS{"directory": {Mode: fs.ModeDir | 0700}}
	directory, _ := entries.Stat("directory")
	backend := &sshOrderBackend{directory: directory, reparse: sshModeInfo{directory, fs.ModeSymlink | 0700}}
	scope := newSSHReadScope(backend)
	defer scope.Close()
	if values, err := scope.ReadDir(`C:\receipts`, 10); err != nil || len(values) != 0 {
		t.Fatalf("initial membership: %v %v", values, err)
	}
	backend.entries = []fs.DirEntry{fs.FileInfoToDirEntry(sshNameInfo{directory, "new.json"})}
	backend.bad = "new.json"
	values, err := scope.ReadDir(`C:\receipts`, 10)
	if err != nil || len(values) != 1 {
		t.Fatalf("membership reused: %v %v", values, err)
	}
	if _, err := scope.ReadFile(`C:\receipts\new.json`, 1024); err == nil {
		t.Fatal("new reparse receipt followed")
	}
	want := []string{`anchor C:\`, "child receipts", "list receipts", "list receipts", "child new.json", "close new.json"}
	if !reflect.DeepEqual(backend.events, want) {
		t.Fatalf("dynamic read order: %v", backend.events)
	}
}
func TestSSHScopeHandleBudgetClosesEverything(t *testing.T) {
	entries := fstest.MapFS{"directory": {Mode: fs.ModeDir | 0700}}
	directory, _ := entries.Stat("directory")
	backend := &sshOrderBackend{directory: directory}
	scope := newSSHReadScope(backend)
	for i := 0; i < 16383; i++ {
		if _, err := scope.Stat(fmt.Sprintf(`C:\item%d`, i)); err != nil {
			t.Fatal(err)
		}
	}
	before := len(backend.events)
	if _, err := scope.Stat(`C:\overflow`); err == nil {
		t.Fatal("handle budget ignored")
	}
	if len(backend.events) != before {
		t.Fatal("opened beyond handle budget")
	}
	scope.Close()
	if len(backend.events) != before+16384 {
		t.Fatal("budget refusal leaked handles")
	}
	if _, err := scope.Stat(`C:\after-close`); err == nil {
		t.Fatal("closed scope reused")
	}
}

type sshACLFile struct {
	sshHeldFile
	allowed uint32
}

func (f sshACLFile) trust(_ string, authority uint32) error {
	if f.allowed&authority != 0 {
		return fmt.Errorf("untrusted directory rights %#x", f.allowed)
	}
	return nil
}
func sshApplicationTrustFixture(t *testing.T, rootRights, applicationRights uint32) *sshReadScope {
	t.Helper()
	entries := fstest.MapFS{"directory": {Mode: fs.ModeDir | 0700}, "program.exe": {Mode: 0600}}
	directory, _ := entries.Stat("directory")
	executable, _ := entries.Stat("program.exe")
	events := []string{}
	scope := newSSHReadScope(nil)
	for _, entry := range []struct {
		path   string
		info   fs.FileInfo
		rights uint32
	}{
		{`C:\`, directory, rootRights},
		{`C:\application`, directory, applicationRights},
		{`C:\application\program.exe`, executable, 0},
	} {
		file := sshACLFile{&sshOrderFile{info: entry.info, name: entry.path, events: &events}, entry.rights}
		scope.held[entry.path] = file
		scope.order = append(scope.order, file)
	}
	t.Cleanup(func() { scope.Close() })
	return scope
}

func TestSSHApplicationDirectoryRequiresFullWriterTrust(t *testing.T) {
	for _, rights := range []uint32{0x2, 0x4, 0x6} {
		t.Run(fmt.Sprintf("add-rights-%x", rights), func(t *testing.T) {
			scope := sshApplicationTrustFixture(t, 0, rights)
			if err := scope.trusted(`C:\application\program.exe`, "fixture"); err != nil {
				t.Fatalf("ancestor policy unexpectedly broadened: %v", err)
			}
			if err := scope.trusted(`C:\application`, "fixture"); err == nil {
				t.Fatal("application directory accepted untrusted create rights")
			}
		})
	}
	scope := sshApplicationTrustFixture(t, 0x6, 0)
	if err := scope.trusted(`C:\application`, "fixture"); err != nil {
		t.Fatalf("ordinary drive-root create rights refused: %v", err)
	}
	if err := scope.trusted(`C:\application\program.exe`, "fixture"); err != nil {
		t.Fatalf("trusted executable refused: %v", err)
	}
}
