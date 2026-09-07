package windowsinstall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

const previewPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type sshFixtureReader struct {
	machine   *fakeMachine
	config    string
	binary    string
	keygen    string
	key       string
	calls     int
	change    func(*sshNativeObservation)
	afterRead func(int)
}

func (f *sshFixtureReader) inspectSSH(ctx context.Context, r SSHPreparationRequest) (sshNativeObservation, error) {
	f.calls++
	installed, parent, err := loadSSHInstallation(ctx, r, f.machine, f.files())
	if err != nil {
		return sshNativeObservation{}, err
	}
	sid := "S-1-5-21-1-2-3-1001"
	installed.AccountSID = sid
	installed.InteractiveSID = sid
	installed.AuthenticatedSID = sid
	config, err := sshReadImage(f.config, maxSSHConfig)
	if err != nil {
		return sshNativeObservation{}, err
	}
	binary, err := sshReadImage(f.binary, 64<<20)
	if err != nil {
		return sshNativeObservation{}, err
	}
	keygen, err := sshReadImage(f.keygen, 64<<20)
	if err != nil {
		return sshNativeObservation{}, err
	}
	private, err := sshReadPath(f.key, false)
	if err != nil {
		return sshNativeObservation{}, err
	}
	public, err := sshReadImage(f.key+".pub", 16<<10)
	if err != nil {
		return sshNativeObservation{}, err
	}
	policy := []byte("port 22\nlistenaddress 192.0.2.10:22\npubkeyauthentication yes\nauthorizedkeyscommand none\nauthorizedprincipalscommand none\nauthorizedprincipalsfile none\ntrustedusercakeys none\nauthorizedkeysfile .ssh/authorized_keys2 .ssh/authorized_keys\nhostkey " + f.key + "\npasswordauthentication no\n")
	observation := sshNativeObservation{Installed: installed, Parent: parent, Configuration: config, Service: SSHServiceState{InstallationProvenance: "system-directory-openssh-binaries-and-existing-service; capability-inventory-unobserved", OSBuild: "10.0.26100", Name: "sshd", Binary: binary.Pin, BinaryVersion: "9.5.0.0", CommandLine: `"` + f.binary + `"`, Account: "LocalSystem", StartType: "Auto", State: "Running", ServiceSDDL: "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)"}, Keygen: keygen.Pin, HostKeys: []SSHHostKeyPin{{PrivateSource: private, PublicSource: public, PublicKey: previewPublicKey, PublicSHA: digest([]byte(previewPublicKey)), Provenance: "configured-private-key-derived-by-pinned-ssh-keygen; listener-unverified"}}, Firewall: []SSHFirewallRule{{PolicyStore: "PersistentStore", ID: "fixture-ssh", Enabled: true, Direction: "Inbound", Action: "Allow", Profiles: []string{"private"}, Protocol: "TCP", LocalAddresses: []string{"192.0.2.10"}, LocalPorts: []string{"22"}, RemoteAddresses: []string{"198.51.100.0/24"}, RemotePorts: []string{"Any"}, Program: "Any", Service: "Any", InterfaceTypes: []string{"Any"}, EdgeTraversal: "Block"}}, Policies: []sshPolicyObservation{{Account: r.Account, SID: sid, Groups: []string{"S-1-5-32-545"}, Text: policy}, {Account: r.ControlAccounts[0], SID: "S-1-5-21-1-2-3-1002", Groups: []string{"S-1-5-32-545"}, Text: slices.Clone(policy)}}}
	if f.change != nil {
		f.change(&observation)
	}
	if f.afterRead != nil {
		f.afterRead(f.calls)
	}
	return observation, nil
}
func sshPreviewFixture(t *testing.T) (*owner, *sshFixtureReader, SSHPreparationRequest) {
	t.Helper()
	return sshPreviewAccountFixture(t, "fixture")
}
func sshPreviewAccountFixture(t *testing.T, installedAccount string) (*owner, *sshFixtureReader, SSHPreparationRequest) {
	t.Helper()
	installer, machine, request := installFixture(t)
	machine.inspection.OwnerSID = "S-1-5-21-1-2-3-1001"
	request.WindowsUser = installedAccount
	initial, err := installer.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.InstallationID = initial.InstallationID
	request.OperationID = initial.OperationID
	request.ExpectedPlan = initial.Plan.PlanSHA256
	request.Apply = true
	installed, err := installer.Execute(context.Background(), request)
	if err != nil || installed.State != "installed" {
		t.Fatalf("fixture installation: %+v %v", installed, err)
	}
	root := filepath.Dir(request.StateRoot)
	reader := &sshFixtureReader{machine: machine, config: filepath.Join(root, "sshd_config"), binary: filepath.Join(root, "sshd.exe"), keygen: filepath.Join(root, "ssh-keygen.exe"), key: filepath.Join(root, "host_ed25519")}
	for path, data := range map[string][]byte{reader.config: []byte("# retained exact bytes\r\nPort 22\r\nHostKey " + reader.key + "\r\nAuthorizedKeysFile .ssh/authorized_keys2 .ssh/authorized_keys\r\n"), reader.binary: []byte("fixture sshd binary"), reader.keygen: []byte("fixture keygen binary"), reader.key: []byte("fixture opaque source, never read by planner"), reader.key + ".pub": []byte(previewPublicKey + " fixture comment\n")} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	owner := newOwner(machine)
	owner.sshRead = reader
	r := SSHPreparationRequest{SchemaVersion: 1, Platform: "windows", InstallationID: request.InstallationID, OperationID: "bbxo_ffffffffffffffffffffffffffffffff", StateRoot: request.StateRoot, Account: "fixture", ControlAccounts: []string{"control"}, Deadline: time.Now().UTC().Add(4 * time.Minute), Connection: SSHConnectionScope{Hostname: "fixture.example", Port: 22, LoginUser: "fixture", LocalAddresses: []string{"192.0.2.10"}, RemotePrefixes: []string{"198.51.100.0/24"}, FirewallProfiles: []string{"private"}}}
	return owner, reader, r
}

type sshInventoryEntry struct {
	Path, Identity string
	Mode           os.FileMode
	Data           string
}

func sshInventory(t *testing.T, root string) []sshInventoryEntry {
	t.Helper()
	entries := []sshInventoryEntry{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		identity, err := fileIdentity(path)
		if err != nil {
			return err
		}
		data := []byte{}
		if info.Mode().IsRegular() {
			data, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		}
		entries = append(entries, sshInventoryEntry{path, identity, info.Mode(), string(data)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return entries
}
func TestSSHPreviewExactStableAndReadOnly(t *testing.T) {
	owner, reader, r := sshPreviewFixture(t)
	before := sshInventory(t, filepath.Dir(r.StateRoot))
	result, err := owner.previewSSH(context.Background(), r)
	if err != nil {
		t.Fatalf("preview: %+v %v", result, err)
	}
	again, err := owner.previewSSH(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := json.Marshal(result)
	second, _ := json.Marshal(again)
	if !bytes.Equal(first, second) {
		t.Fatal("same request and files changed result")
	}
	if !reflect.DeepEqual(before, sshInventory(t, filepath.Dir(r.StateRoot))) {
		t.Fatal("preview changed complete file inventory")
	}
	body := result.Plan.Body
	if reader.calls != 4 || body.Source.InitialBytes == nil || len(body.Source.InitialBytes) != 0 || !strings.Contains(body.Source.FileSDDL, "D:P") || !strings.Contains(body.Source.DirectorySDDL, r.Account) && !strings.Contains(body.Source.DirectorySDDL, body.Installed.AccountSID) {
		t.Fatal("incomplete source or observations")
	}
	config, _ := os.ReadFile(reader.config)
	expectedInsertion := "Match User fixture\r\n    AuthorizedKeysFile .ssh/authorized_keys2 .ssh/authorized_keys " + filepath.ToSlash(body.Source.File) + "\r\nMatch all\r\n"
	if !bytes.Equal(body.Configuration.Before.Bytes, config) || string(body.Configuration.InsertBytes) != expectedInsertion || !bytes.Equal(body.Configuration.AfterBytes, append(slices.Clone(config), []byte(expectedInsertion)...)) {
		t.Fatalf("lossy config: %q", body.Configuration.InsertBytes)
	}
	selected, control := body.Policies[0], body.Policies[1]
	if !slices.Equal(selected.PriorSources, []string{".ssh/authorized_keys2", ".ssh/authorized_keys"}) || selected.BeforeSHA == selected.AfterSHA || !selected.NativeProofRequired || !control.NativeProofRequired || !bytes.Equal(control.NativeBefore, control.PredictedAfter) {
		t.Fatal("source order or prediction provenance changed")
	}
	if result.Plan.PlanSHA256 != sshDomainDigest("blender-box-ssh-preparation-plan-v1\x00", body) {
		t.Fatal("wrong plan domain digest")
	}
	if body.RequestSHA256 != sshDomainDigest("blender-box-ssh-preparation-request-v1\x00", r) {
		t.Fatal("wrong request domain digest")
	}
	if !strings.Contains(body.HostKeys[0].Provenance, "listener-unverified") {
		t.Fatal("configured public key incorrectly claims listener proof")
	}
}
func TestSSHPreviewChangedDependencies(t *testing.T) {
	tests := map[string]func(*sshNativeObservation){
		"config-bytes": func(o *sshNativeObservation) {
			o.Configuration.Bytes = append(o.Configuration.Bytes, []byte("# new observation\r\n")...)
			o.Configuration.Pin.Size = int64(len(o.Configuration.Bytes))
			o.Configuration.Pin.BytesSHA = digest(o.Configuration.Bytes)
		},
		"config-identity":   func(o *sshNativeObservation) { o.Configuration.Pin.Path.PhysicalID += "-new" },
		"config-acl":        func(o *sshNativeObservation) { o.Configuration.Pin.Path.DescriptorSHA = digest([]byte("changed")) },
		"receipt-identity":  func(o *sshNativeObservation) { o.Installed.Receipt.Pin.Path.PhysicalID += "-new" },
		"root-identity":     func(o *sshNativeObservation) { o.Installed.Root.PhysicalID += "-new" },
		"root-acl":          func(o *sshNativeObservation) { o.Installed.Root.DescriptorSHA = digest([]byte("changed")) },
		"binary":            func(o *sshNativeObservation) { o.Service.Binary.BytesSHA = digest([]byte("changed")) },
		"keygen":            func(o *sshNativeObservation) { o.Keygen.BytesSHA = digest([]byte("changed")) },
		"host-key-metadata": func(o *sshNativeObservation) { o.HostKeys[0].PrivateSource.PhysicalID += "-new" },
		"effective-policy": func(o *sshNativeObservation) {
			o.Policies[0].Text = bytes.ReplaceAll(o.Policies[0].Text, []byte("passwordauthentication no"), []byte("passwordauthentication yes"))
		},
		"service-acl": func(o *sshNativeObservation) { o.Service.ServiceSDDL += "(A;;GR;;;BU)" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			owner, reader, r := sshPreviewFixture(t)
			before, err := owner.previewSSH(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			reader.change = change
			after, err := owner.previewSSH(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			if before.Plan.PlanSHA256 == after.Plan.PlanSHA256 {
				t.Fatal("changed dependency retained same digest")
			}
		})
	}
}
func TestSSHPreviewRefusesUnsupportedObservations(t *testing.T) {
	tests := map[string]func(*sshNativeObservation){
		"sid":                    func(o *sshNativeObservation) { o.Installed.AccountSID = "S-1-5-21-1-2-3-1003" },
		"interactive":            func(o *sshNativeObservation) { o.Installed.InteractiveSID = "S-1-5-21-1-2-3-1003" },
		"authenticated":          func(o *sshNativeObservation) { o.Installed.AuthenticatedSID = "S-1-5-21-1-2-3-1003" },
		"task":                   func(o *sshNativeObservation) { o.Installed.TaskFingerprint = digest([]byte("other")) },
		"runtime":                func(o *sshNativeObservation) { o.Installed.RuntimeFiles = nil },
		"receipt-substitution":   func(o *sshNativeObservation) { o.Installed.Receipt.Pin.Path.Path += ".other" },
		"missing-provenance":     func(o *sshNativeObservation) { o.Service.InstallationProvenance = "" },
		"stopped-service":        func(o *sshNativeObservation) { o.Service.State = "Stopped" },
		"service-arguments":      func(o *sshNativeObservation) { o.Service.CommandLine += " -f other" },
		"version":                func(o *sshNativeObservation) { o.Service.BinaryVersion = "99.0" },
		"firewall-broader":       func(o *sshNativeObservation) { o.Firewall[0].RemoteAddresses = []string{"Any"} },
		"firewall-keyword":       func(o *sshNativeObservation) { o.Firewall[0].RemoteAddresses = []string{"LocalSubnet"} },
		"firewall-group-policy":  func(o *sshNativeObservation) { o.Firewall[0].PolicyStore = "GroupPolicy" },
		"firewall-duplicate":     func(o *sshNativeObservation) { o.Firewall = append(o.Firewall, o.Firewall[0]) },
		"administrator":          func(o *sshNativeObservation) { o.Policies[0].Administrator = true },
		"same-control-sid":       func(o *sshNativeObservation) { o.Policies[1].SID = o.Policies[0].SID },
		"key-companion-mismatch": func(o *sshNativeObservation) { o.HostKeys[0].PublicKey += "other" },
		"key-missing":            func(o *sshNativeObservation) { o.HostKeys = nil },
		"key-extra":              func(o *sshNativeObservation) { o.HostKeys = append(o.HostKeys, o.HostKeys[0]) },
		"policy-duplicate":       func(o *sshNativeObservation) { o.Policies[0].Text = append(o.Policies[0].Text, []byte("port 22\n")...) },
		"policy-shared-source": func(o *sshNativeObservation) {
			o.Policies[0].Text = bytes.ReplaceAll(o.Policies[0].Text, []byte(".ssh/authorized_keys2 .ssh/authorized_keys"), []byte("__PROGRAMDATA__/ssh/administrators_authorized_keys"))
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			owner, reader, r := sshPreviewFixture(t)
			reader.change = change
			before := sshInventory(t, filepath.Dir(r.StateRoot))
			result, err := owner.previewSSH(context.Background(), r)
			if err == nil || result.Plan != nil || result.State != "refused" {
				t.Fatalf("accepted %+v %v", result, err)
			}
			if !reflect.DeepEqual(before, sshInventory(t, filepath.Dir(r.StateRoot))) {
				t.Fatal("refusal changed files")
			}
		})
	}
}
func TestSSHPreviewActualFileChangesAndStaleRead(t *testing.T) {
	for _, kind := range []string{"config", "receipt", "root-mode", "config-replacement", "collision", "match", "include", "runtime"} {
		t.Run(kind, func(t *testing.T) {
			owner, reader, r := sshPreviewFixture(t)
			original, err := owner.previewSSH(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			expectRefusal := true
			switch kind {
			case "config":
				file, err := os.OpenFile(reader.config, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = file.WriteString("# extra\r\n")
				file.Close()
				if err != nil {
					t.Fatal(err)
				}
				expectRefusal = false
			case "receipt":
				path := filepath.Join(r.StateRoot, "installations", string(r.InstallationID), "receipt.json")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
				expectRefusal = false
			case "root-mode":
				if runtime.GOOS == "windows" {
					t.Skip("POSIX mode bits; native DACL digest covered separately")
				}
				if err := os.Chmod(r.StateRoot, 0750); err != nil {
					t.Fatal(err)
				}
			case "config-replacement":
				path := reader.config + ".replacement"
				data, _ := os.ReadFile(reader.config)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path, reader.config); err != nil {
					t.Fatal(err)
				}
				expectRefusal = false
			case "collision":
				if err := os.Mkdir(original.Plan.Body.Source.Directory, 0700); err != nil {
					t.Fatal(err)
				}
			case "match", "include":
				if err := os.WriteFile(reader.config, []byte(strings.Title(kind)+" all\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "runtime":
				for _, pin := range original.Plan.Body.Installed.RuntimeFiles {
					if pin.Size > 0 {
						if err := os.WriteFile(pin.Path.Path, []byte("operator change"), 0600); err != nil {
							t.Fatal(err)
						}
						break
					}
				}
			}
			before := sshInventory(t, filepath.Dir(r.StateRoot))
			result, err := owner.previewSSH(context.Background(), r)
			if expectRefusal && (err == nil || result.Plan != nil) {
				t.Fatalf("accepted changed %s", kind)
			}
			if !expectRefusal && (err != nil || result.Plan.PlanSHA256 == original.Plan.PlanSHA256) {
				t.Fatalf("change not reflected %s: %v", kind, err)
			}
			if !reflect.DeepEqual(before, sshInventory(t, filepath.Dir(r.StateRoot))) {
				t.Fatal("preview changed fixture")
			}
		})
	}
	owner, reader, r := sshPreviewFixture(t)
	reader.afterRead = func(call int) {
		if call == 1 {
			if err := os.WriteFile(reader.config, []byte("# race\nHostKey "+reader.key+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	result, err := owner.previewSSH(context.Background(), r)
	if err == nil || result.Plan != nil || result.Problems[0].Code != "observation-changed" {
		t.Fatalf("stale accepted: %+v %v", result, err)
	}
}
func TestSSHPreviewGrammarAndBoundedNativeDecoding(t *testing.T) {
	for _, input := range []string{"{}{}", `{"value":"a","value":"b"}`, `{"unknown":true}`, `{"value":null}`, string(bytes.Repeat([]byte("x"), (1<<20)+1)), "\xff"} {
		var output struct {
			Value string `json:"value"`
		}
		if err := decodeSSHObservation([]byte(input), &output); err == nil {
			t.Errorf("accepted native output %q", input[:min(80, len(input))])
		}
	}
	for _, input := range []string{"Include x\n", "Match User fixture\n", "Port 22\nPort 2222\n", "HostKey \"a b\"\n", "Port 22\r\nHostKey /x\n", "Port 22\x00\n", string(bytes.Repeat([]byte("#"), maxSSHConfig+1))} {
		if _, err := sshConfig([]byte(input)); err == nil {
			t.Fatalf("accepted config %q", input[:min(80, len(input))])
		}
	}
	output, values, err := sshPolicy([]byte("port 22\nlistenaddress [2001:db8::1]:22\nlistenaddress 192.0.2.10:22\n"))
	if err != nil || values["listenaddress"] != "[2001:db8::1]:22\n192.0.2.10:22" || !bytes.HasPrefix(output, []byte("listenaddress [2001:db8::1]:22\nlistenaddress 192.0.2.10:22\n")) {
		t.Fatalf("ordered repeated fields: %q %v", output, err)
	}
	for _, input := range []string{previewPublicKey + "\n" + previewPublicKey, previewPublicKey + "\nextra\n", "ssh-rsa invalid", previewPublicKey + "\x00"} {
		if _, err := sshPublic([]byte(input)); err == nil {
			t.Fatalf("accepted malformed public key %q", input)
		}
	}
	if public, err := sshPublic([]byte(previewPublicKey + " harmless fixture comment\r\n")); err != nil || public != previewPublicKey {
		t.Fatalf("canonical public material: %q %v", public, err)
	}
}
func TestSSHPreviewInvalidRequestsBeforeObservation(t *testing.T) {
	for name, change := range map[string]func(*SSHPreparationRequest){"expired": func(r *SSHPreparationRequest) { r.Deadline = time.Now().UTC().Add(-time.Second) }, "too-long": func(r *SSHPreparationRequest) { r.Deadline = time.Now().UTC().Add(time.Hour) }, "admin-token": func(r *SSHPreparationRequest) { r.Account = "fixture*" }, "independent": func(r *SSHPreparationRequest) { r.ControlAccounts = []string{r.Account} }, "unsorted": func(r *SSHPreparationRequest) { r.Connection.LocalAddresses = []string{"192.0.2.2", "192.0.2.1"} }, "unmasked-prefix": func(r *SSHPreparationRequest) { r.Connection.RemotePrefixes = []string{"198.51.100.1/24"} }, "wildcard-local": func(r *SSHPreparationRequest) { r.Connection.LocalAddresses = []string{"0.0.0.0"} }, "implicit-login": func(r *SSHPreparationRequest) { r.Connection.LoginUser = "" }, "too-many-controls": func(r *SSHPreparationRequest) { r.ControlAccounts = make([]string, 9) }, "bad-id": func(r *SSHPreparationRequest) { r.OperationID = "" }} {
		t.Run(name, func(t *testing.T) {
			owner, reader, r := sshPreviewFixture(t)
			change(&r)
			result, err := owner.previewSSH(context.Background(), r)
			if err == nil || result.Plan != nil || reader.calls != 0 {
				t.Fatalf("invalid request observed: %+v %v calls=%d", result, err, reader.calls)
			}
		})
	}
}
func TestSSHPreviewDigestKnownDomain(t *testing.T) {
	actual := sshDomainDigest("blender-box-ssh-preparation-plan-v1\x00", struct {
		Version int `json:"version"`
	}{1})
	expected := digest([]byte("blender-box-ssh-preparation-plan-v1\x00{\"version\":1}"))
	if actual != expected {
		t.Fatal(fmt.Sprintf("domain mismatch %s != %s", actual, expected))
	}
}

func TestSSHPreviewAdministratorControlAndMembership(t *testing.T) {
	owner, reader, request := sshPreviewFixture(t)
	reader.change = func(o *sshNativeObservation) {
		for i := range o.Policies {
			o.Policies[i].Administrator = true
			o.Policies[i].Groups = []string{"S-1-5-32-544", "S-1-5-32-545"}
		}
	}
	before := sshInventory(t, filepath.Dir(request.StateRoot))
	result, err := owner.previewSSH(context.Background(), request)
	if err != nil || !result.Plan.Body.Policies[0].Administrator || !slices.Equal(result.Plan.Body.Policies[0].Groups, []string{"S-1-5-32-544", "S-1-5-32-545"}) {
		t.Fatalf("same-account administrator preview: %+v %v", result, err)
	}
	reader.change = func(o *sshNativeObservation) {
		o.Policies[0].Administrator = true
		o.Policies[0].Groups = []string{"S-1-5-32-544", "S-1-5-32-545"}
	}
	refused, err := owner.previewSSH(context.Background(), request)
	if err == nil || refused.Plan != nil || !strings.Contains(err.Error(), "administrator control") {
		t.Fatalf("missing administrator control accepted: %+v %v", refused, err)
	}
	reader.change = nil
	ordinary, err := owner.previewSSH(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	reader.change = func(o *sshNativeObservation) { o.Policies[0].Groups = append(o.Policies[0].Groups, "S-1-5-32-546") }
	changed, err := owner.previewSSH(context.Background(), request)
	if err != nil || ordinary.Plan.PlanSHA256 == changed.Plan.PlanSHA256 {
		t.Fatalf("membership not bound: %+v %v", changed, err)
	}
	if !reflect.DeepEqual(before, sshInventory(t, filepath.Dir(request.StateRoot))) {
		t.Fatal("account preview changed files")
	}
}

func TestSSHPreviewExistingOperationRefused(t *testing.T) {
	owner, _, request := sshPreviewFixture(t)
	path := filepath.Join(request.StateRoot, "setup-operations", string(request.OperationID))
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	before := sshInventory(t, filepath.Dir(request.StateRoot))
	result, err := owner.previewSSH(context.Background(), request)
	if err == nil || result.Plan != nil || !strings.Contains(err.Error(), "operation ID") {
		t.Fatalf("reused operation accepted: %+v %v", result, err)
	}
	if !reflect.DeepEqual(before, sshInventory(t, filepath.Dir(request.StateRoot))) {
		t.Fatal("operation refusal changed files")
	}
}

func TestSSHPreviewPolicyBounds(t *testing.T) {
	for _, input := range []string{
		strings.Repeat("listenaddress 192.0.2.1:22\n", 17),
		"versionaddendum " + strings.Repeat("x", 8192) + "\n",
		strings.Repeat("listenaddress 192.0.2.1:22\n", 257),
	} {
		if _, _, err := sshPolicy([]byte(input)); err == nil {
			t.Fatal("unbounded native policy accepted")
		}
	}
}

func TestSSHPreviewNativePolicyLineEndings(t *testing.T) {
	owner, reader, request := sshPreviewFixture(t)
	reader.change = func(o *sshNativeObservation) {
		for i := range o.Policies {
			o.Policies[i].Text = bytes.ReplaceAll(o.Policies[i].Text, []byte("\n"), []byte("\r\n"))
		}
	}
	result, err := owner.previewSSH(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range result.Plan.Body.Policies {
		if !bytes.Contains(policy.NativeBefore, []byte("\r\n")) || policy.BeforeSHA != digest(policy.NativeBefore) {
			t.Fatal("raw native output lost")
		}
	}
	control := result.Plan.Body.Policies[1]
	if !bytes.Equal(control.NativeBefore, control.PredictedAfter) {
		t.Fatal("control policy changed")
	}
	for _, text := range []string{"port 22\r\nlistenaddress 192.0.2.1:22\n", "port 22\rlistenaddress 192.0.2.1:22\n"} {
		if _, _, err := sshPolicy([]byte(text)); err == nil {
			t.Fatal("mixed or bare CR accepted")
		}
	}
}

func TestSSHPreviewInstalledAccountCase(t *testing.T) {
	owner, _, request := sshPreviewAccountFixture(t, "Fixture")
	before := sshInventory(t, filepath.Dir(request.StateRoot))
	result, err := owner.previewSSH(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	var receipt installationReceipt
	if err := json.Unmarshal(result.Plan.Body.Installed.Receipt.Bytes, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Intent.WindowsUser != "Fixture" || !strings.Contains(string(result.Plan.Body.Configuration.InsertBytes), "Match User fixture\r\n") {
		t.Fatal("lost installed spelling or canonical Match account")
	}
	if !reflect.DeepEqual(before, sshInventory(t, filepath.Dir(request.StateRoot))) {
		t.Fatal("case-equivalent preview changed receipt")
	}
}

type sshFixtureFiles struct{ machine *fakeMachine }

func (f *sshFixtureReader) files() sshFilesystem                { return sshFixtureFiles{f.machine} }
func (*sshFixtureReader) Close() error                          { return nil }
func (f sshFixtureFiles) Stat(path string) (fs.FileInfo, error) { return os.Lstat(path) }
func (f sshFixtureFiles) ReadDir(path string, maximum int) ([]fs.DirEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries, err := file.ReadDir(maximum + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return entries, nil
}
func (f sshFixtureFiles) ReadFile(path string, maximum int) ([]byte, error) {
	image, err := sshReadImage(path, maximum)
	return image.Bytes, err
}
func (f sshFixtureFiles) pin(path string, directory bool) (SSHPathPin, error) {
	return sshReadPath(path, directory)
}
func (f sshFixtureFiles) image(path string, maximum int) (SSHByteImage, error) {
	return sshReadImage(path, maximum)
}
func (f sshFixtureFiles) identity(path string) (string, error) { return fileIdentity(path) }
func (f sshFixtureFiles) trusted(path, sid string) error {
	return f.machine.securePath(context.Background(), path, sid, false)
}
func sshReadPath(path string, directory bool) (SSHPathPin, error) {
	if err := checkPath(path, false); err != nil {
		return SSHPathPin{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return SSHPathPin{}, err
	}
	if info.IsDir() != directory {
		return SSHPathPin{}, fmt.Errorf("unexpected fixture file type")
	}
	identity, err := fileIdentity(path)
	if err != nil {
		return SSHPathPin{}, err
	}
	return SSHPathPin{Path: path, PhysicalID: identity, DescriptorSHA: digest([]byte(identity))}, nil
}
func sshReadImage(path string, maximum int) (SSHByteImage, error) {
	before, err := sshReadPath(path, false)
	if err != nil {
		return SSHByteImage{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return SSHByteImage{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return SSHByteImage{}, err
	}
	after, err := sshReadPath(path, false)
	if err != nil || before != after || len(data) > maximum {
		return SSHByteImage{}, fmt.Errorf("fixture file changed")
	}
	return SSHByteImage{Pin: SSHFilePin{Path: before, Size: int64(len(data)), BytesSHA: digest(data)}, Bytes: data}, nil
}

func TestSSHPolicyAcceptEnvOrderAndBounds(t *testing.T) {
	t.Run("ordered-native-array", func(t *testing.T) {
		forward, values, err := sshPolicy([]byte("port 22\nacceptenv LANG\nacceptenv LC_*\n"))
		if err != nil || values["acceptenv"] != "LANG\nLC_*" || string(forward) != "acceptenv LANG\nacceptenv LC_*\nport 22\n" {
			t.Fatalf("ordered AcceptEnv rejected or changed: output=%q values=%v error=%v", forward, values, err)
		}
		reverse, values, err := sshPolicy([]byte("port 22\nacceptenv LC_*\nacceptenv LANG\n"))
		if err != nil || values["acceptenv"] != "LC_*\nLANG" || string(reverse) != "acceptenv LC_*\nacceptenv LANG\nport 22\n" {
			t.Fatalf("reversed AcceptEnv rejected or changed: output=%q values=%v error=%v", reverse, values, err)
		}
		if digest(forward) == digest(reverse) {
			t.Fatal("AcceptEnv ordering disappeared from policy digest")
		}
	})
	for _, count := range []int{16, 17} {
		t.Run(fmt.Sprintf("repetitions-%d", count), func(t *testing.T) {
			var policy strings.Builder
			var want []string
			for i := 0; i < count; i++ {
				value := fmt.Sprintf("VARIABLE_%02d", i)
				want = append(want, value)
				fmt.Fprintf(&policy, "acceptenv %s\n", value)
			}
			output, values, err := sshPolicy([]byte(policy.String()))
			if count == 17 {
				if err == nil || !strings.Contains(err.Error(), "excessive native policy repetitions") {
					t.Fatalf("AcceptEnv repetition bound: %v", err)
				}
				return
			}
			if err != nil || string(output) != policy.String() || values["acceptenv"] != strings.Join(want, "\n") {
				t.Fatalf("bounded AcceptEnv array rejected or changed: output=%q values=%v error=%v", output, values, err)
			}
		})
	}
}

func TestSSHPreviewAcceptEnvConfiguration(t *testing.T) {
	for name, directives := range map[string]string{"multivalue": "AcceptEnv LANG LC_*\r\n", "repeated": "AcceptEnv LANG\r\nAcceptEnv LC_*\r\n"} {
		t.Run(name, func(t *testing.T) {
			owner, reader, request := sshPreviewFixture(t)
			config, err := os.ReadFile(reader.config)
			if err != nil {
				t.Fatal(err)
			}
			config = append(config, []byte(directives)...)
			if _, err := sshConfig(config); err != nil {
				t.Fatalf("supported AcceptEnv config rejected: %v", err)
			}
			if err := os.WriteFile(reader.config, config, 0600); err != nil {
				t.Fatal(err)
			}
			reader.change = func(observed *sshNativeObservation) {
				for i := range observed.Policies {
					observed.Policies[i].Text = append(observed.Policies[i].Text, []byte("acceptenv LANG\nacceptenv LC_*\n")...)
				}
			}
			result, err := owner.previewSSH(context.Background(), request)
			if err != nil || result.Plan == nil {
				t.Fatalf("supported config's native policy refused: %+v %v", result, err)
			}
			for _, policy := range result.Plan.Body.Policies {
				if !bytes.HasSuffix(policy.NativeBefore, []byte("acceptenv LANG\nacceptenv LC_*\n")) || policy.BeforeSHA != digest(policy.NativeBefore) {
					t.Fatalf("native AcceptEnv evidence changed: %+v", policy)
				}
			}
		})
	}
}
