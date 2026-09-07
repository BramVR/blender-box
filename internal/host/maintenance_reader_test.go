package host

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/orchestrator"
)

type mappedMaintenanceReader struct {
	root, physical string
	reads          []string
}

func (r *mappedMaintenanceReader) path(path string) string {
	relative, err := filepath.Rel(r.root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		panic("maintenance escaped reader")
	}
	return filepath.Join(r.physical, relative)
}
func (r *mappedMaintenanceReader) Stat(path string) (fs.FileInfo, error) {
	r.reads = append(r.reads, "stat")
	return os.Lstat(r.path(path))
}
func (r *mappedMaintenanceReader) ReadDir(path string, maximum int) ([]fs.DirEntry, error) {
	if maximum != 4096 {
		panic("unbounded maintenance directory read")
	}
	r.reads = append(r.reads, "directory")
	return (maintenanceFiles{}).ReadDir(r.path(path), maximum)
}
func (r *mappedMaintenanceReader) ReadFile(path string, maximum int) ([]byte, error) {
	if maximum != maxScenarioJSON && maximum != 16<<10 {
		panic("unbounded maintenance file read")
	}
	r.reads = append(r.reads, "file")
	return (maintenanceFiles{}).ReadFile(r.path(path), maximum)
}
func TestMaintenanceInjectedReaderPolicyParity(t *testing.T) {
	claim := SetupClaim{SchemaVersion: 1, InstallationID: "bbxi_" + strings.Repeat("a", 32), OperationID: "bbxo_" + strings.Repeat("b", 32), ExecutionToken: "bbxe_" + strings.Repeat("c", 32), RequestSHA256: strings.Repeat("d", 64), RootIdentity: "fixture", OwnerSID: "fixture", Deadline: time.Now().UTC().Add(time.Minute)}
	claimData, _ := json.Marshal(claim)
	runClaim := testHostClaim(time.Now(), "M")
	receipt := orchestrator.RunReceipt{SchemaVersion: 1, Claim: runClaim, State: orchestrator.StateComplete, Cleanup: orchestrator.CleanupState{SessionStopped: true, PayloadRemoved: true, RunRootRemoved: true, LockReleased: true}}
	receiptData, _ := json.Marshal(receipt)
	cases := []struct {
		name   string
		files  map[string][]byte
		own    *SetupClaim
		absent bool
	}{
		{name: "absent", absent: true}, {name: "empty"},
		{name: "pending", files: map[string][]byte{"pending-setup.json": claimData}},
		{name: "exact", files: map[string][]byte{"pending-setup.json": claimData}, own: &claim},
		{name: "corrupt-claim", files: map[string][]byte{"pending-setup.json": []byte(`{"schema_version":1,"schema_version":1}`)}, own: &claim},
		{name: "lock", files: map[string][]byte{"host-lock.json": {}}},
		{name: "request", files: map[string][]byte{"pending-request.json": {}}},
		{name: "run", files: map[string][]byte{"runs/entry": {}}},
		{name: "corrupt-receipt", files: map[string][]byte{"receipts/bad.json": []byte(`{}`)}},
		{name: "duplicate-receipt", files: map[string][]byte{"receipts/bad.json": []byte(`{"schema_version":1,"schema_version":1}`)}},
		{name: "settled", files: map[string][]byte{"receipts/" + string(runClaim.RunID) + ".json": receiptData}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(privateTempDir(t), "root")
			if !test.absent {
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
			}
			for name, data := range test.files {
				path := filepath.Join(root, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			expected := InspectSetupMaintenance(root, test.own)
			reader := &mappedMaintenanceReader{root: filepath.Join(privateTempDir(t), "virtual-never-created"), physical: root}
			actual := InspectSetupMaintenanceWithReader(reader.root, test.own, reader)
			if fmt.Sprint(actual) != fmt.Sprint(expected) {
				t.Fatalf("policy changed: default=%v injected=%v", expected, actual)
			}
			if len(reader.reads) == 0 {
				t.Fatal("injected reader unused")
			}
			if _, err := os.Lstat(reader.root); !os.IsNotExist(err) {
				t.Fatal("inspection created logical root")
			}
		})
	}
	mismatched := claim
	mismatched.ExecutionToken = "bbxe_" + strings.Repeat("e", 32)
	root := privateTempDir(t)
	if err := os.WriteFile(filepath.Join(root, "pending-setup.json"), claimData, 0600); err != nil {
		t.Fatal(err)
	}
	reader := &mappedMaintenanceReader{root: root, physical: root}
	if err := InspectSetupMaintenanceWithReader(root, &mismatched, reader); err == nil {
		t.Fatal("foreign setup claim accepted")
	}
	if !reflect.DeepEqual(reader.reads, []string{"stat", "stat", "file"}) {
		t.Fatalf("setup read bypass or duplicate: %v", reader.reads)
	}
}
