package windowsinstall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/BramVR/blender-box/internal/host"
	"github.com/BramVR/blender-box/internal/sshkey"
	"github.com/BramVR/blender-box/internal/strictjson"
	"github.com/BramVR/blender-box/internal/windowstarget"
)

const maxSSHConfig = 256 << 10
const maxSSHObservation = 8 << 20

var sshAccount = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
var sshSID = regexp.MustCompile(`^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$`)
var sshPolicyName = regexp.MustCompile(`^[a-z][a-z0-9]*$`)
var sshGroupSID = regexp.MustCompile(`^S-1-[0-9]+(?:-[0-9]+){1,14}$`)

var sshHostname = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,252}$`)

type sshFilesystem interface {
	host.MaintenanceReader
	pin(string, bool) (SSHPathPin, error)
	image(string, int) (SSHByteImage, error)
	identity(string) (string, error)
	trusted(string, string) error
}
type sshReadBoundary interface {
	files() sshFilesystem
	Close() error
	inspectSSH(context.Context, SSHPreparationRequest) (sshNativeObservation, error)
}
type sshPolicyObservation struct {
	Account       string   `json:"account"`
	SID           string   `json:"sid"`
	Administrator bool     `json:"administrator"`
	Groups        []string `json:"groups"`
	Text          []byte   `json:"text"`
}
type sshNativeObservation struct {
	Installed     SSHInstalledScope      `json:"installed"`
	Parent        SSHPathPin             `json:"parent"`
	Configuration SSHByteImage           `json:"configuration"`
	Service       SSHServiceState        `json:"service"`
	Keygen        SSHFilePin             `json:"keygen"`
	HostKeys      []SSHHostKeyPin        `json:"host_keys"`
	Firewall      []SSHFirewallRule      `json:"firewall"`
	Policies      []sshPolicyObservation `json:"policies"`
}

// PreviewSSH reads existing Windows state and returns a proposal without execution authority.
func PreviewSSH(ctx context.Context, request SSHPreparationRequest) (SSHPreparationPreviewResult, error) {
	return newOwner(nativeMachine{}).previewSSH(ctx, request)
}
func sshRefuse(code string, err error) (SSHPreparationPreviewResult, error) {
	return SSHPreparationPreviewResult{SchemaVersion: 1, State: "refused", Problems: []Problem{{Code: code, Message: err.Error()}}}, err
}
func (o *owner) previewSSH(ctx context.Context, r SSHPreparationRequest) (SSHPreparationPreviewResult, error) {
	reader := o.sshRead
	if reader == nil {
		if err := validateSSHRequest(r); err != nil {
			return sshRefuse("invalid-request", err)
		}
		var err error
		reader, err = newSSHNativeReader()
		if err != nil {
			return sshRefuse("unsupported-platform", err)
		}
	} else if err := validateSSHRequestFields(r); err != nil {
		return sshRefuse("invalid-request", err)
	}
	defer reader.Close()
	ctx, cancel := context.WithDeadline(ctx, r.Deadline)
	defer cancel()
	before, err := reader.inspectSSH(ctx, r)
	if err != nil {
		code := "inspection-failed"
		if runtime.GOOS != "windows" && o.sshRead == nil {
			code = "unsupported-platform"
		}
		return sshRefuse(code, err)
	}
	after, err := reader.inspectSSH(ctx, r)
	if err != nil {
		return sshRefuse("observation-changed", err)
	}
	if objectDigest(before) != objectDigest(after) {
		return sshRefuse("observation-changed", fmt.Errorf("SSH dependencies changed during preview"))
	}
	if err := host.InspectSetupMaintenanceWithReader(r.StateRoot, nil, reader.files()); err != nil {
		return sshRefuse("maintenance-conflict", err)
	}
	if err := ctx.Err(); err != nil {
		return sshRefuse("deadline", err)
	}
	plan, err := buildSSHPreparationPlan(r, before)
	if err != nil {
		return sshRefuse("unsupported-scope", err)
	}
	return SSHPreparationPreviewResult{SchemaVersion: 1, State: "previewed", Plan: &plan, Problems: []Problem{}}, nil
}
func validateSSHRequest(r SSHPreparationRequest) error {
	if !windowstarget.ValidateWindowsPath(r.StateRoot) {
		return fmt.Errorf("state root must use canonical fixed-local Windows grammar")
	}
	return validateSSHRequestFields(r)
}
func validateSSHRequestFields(r SSHPreparationRequest) error {
	data, err := json.Marshal(r)
	if err != nil || len(data) > 64<<10 || !utf8.Valid(data) {
		return fmt.Errorf("SSH request exceeds bounds")
	}
	if r.SchemaVersion != 1 || r.Platform != "windows" || !installID.MatchString(string(r.InstallationID)) || !operationID.MatchString(string(r.OperationID)) {
		return fmt.Errorf("Windows schema 1 and exact installation/operation IDs required")
	}
	remaining := time.Until(r.Deadline)
	if remaining <= 0 || remaining > 5*time.Minute || r.Deadline.Location() != time.UTC {
		return fmt.Errorf("deadline must be UTC, future and within five minutes")
	}
	if !sshAccount.MatchString(r.Account) || r.Account != r.Connection.LoginUser {
		return fmt.Errorf("selected local account and login must be identical canonical lowercase names")
	}
	if !sshHostname.MatchString(r.Connection.Hostname) || r.Connection.Port == 0 {
		return fmt.Errorf("explicit canonical hostname and port required")
	}
	if len(r.ControlAccounts) < 1 || len(r.ControlAccounts) > 8 || !sortedUnique(r.ControlAccounts) {
		return fmt.Errorf("one to eight sorted distinct control accounts required")
	}
	for _, account := range r.ControlAccounts {
		if !sshAccount.MatchString(account) || account == r.Account {
			return fmt.Errorf("control account must be independent")
		}
	}
	if err := validateSSHNetwork(r.Connection); err != nil {
		return err
	}
	return nil
}
func sortedUnique(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for i, value := range values {
		if value == "" || i > 0 && values[i-1] >= value {
			return false
		}
	}
	return true
}
func validateSSHNetwork(c SSHConnectionScope) error {
	if len(c.LocalAddresses) > 16 || !sortedUnique(c.LocalAddresses) || len(c.RemotePrefixes) > 16 || !sortedUnique(c.RemotePrefixes) || len(c.FirewallProfiles) > 3 || !sortedUnique(c.FirewallProfiles) {
		return fmt.Errorf("explicit bounded sorted network selectors required")
	}
	for _, value := range c.LocalAddresses {
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.String() != value || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("unsupported local address")
		}
	}
	for _, value := range c.RemotePrefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Masked().String() != value || prefix.Addr().Is4In6() || prefix.Addr().IsMulticast() {
			return fmt.Errorf("unsupported remote prefix")
		}
	}
	for _, value := range c.FirewallProfiles {
		if value != "domain" && value != "private" && value != "public" {
			return fmt.Errorf("unsupported firewall profile")
		}
	}
	return nil
}
func sshImageValid(image SSHByteImage, max int) bool {
	return sshPinValid(image.Pin.Path) && image.Bytes != nil && len(image.Bytes) <= max && image.Pin.Size == int64(len(image.Bytes)) && image.Pin.BytesSHA == digest(image.Bytes)
}
func sshPinValid(pin SSHPathPin) bool {
	return pin.Path != "" && pin.PhysicalID != "" && hex64.MatchString(string(pin.DescriptorSHA))
}
func sshFileValid(pin SSHFilePin) bool {
	return sshPinValid(pin.Path) && pin.Size >= 0 && hex64.MatchString(string(pin.BytesSHA))
}

func loadSSHInstallation(ctx context.Context, r SSHPreparationRequest, machine machine, reader sshFilesystem) (SSHInstalledScope, SSHPathPin, error) {
	var scope SSHInstalledScope
	if err := host.InspectSetupMaintenanceWithReader(r.StateRoot, nil, reader); err != nil {
		return scope, SSHPathPin{}, err
	}
	operation := filepath.Join(r.StateRoot, "setup-operations", string(r.OperationID))
	if _, err := reader.Stat(operation); !os.IsNotExist(err) {
		return scope, SSHPathPin{}, fmt.Errorf("SSH operation ID already exists or cannot be inspected")
	}
	directory := filepath.Join(r.StateRoot, "installations", string(r.InstallationID))
	image, err := reader.image(filepath.Join(directory, "receipt.json"), 2<<20)
	if err != nil {
		return scope, SSHPathPin{}, err
	}
	receipt, err := sshReceipt(r, image)
	if err != nil {
		return scope, SSHPathPin{}, err
	}
	root, err := reader.pin(r.StateRoot, true)
	if err != nil {
		return scope, SSHPathPin{}, err
	}
	identity, err := reader.identity(r.StateRoot)
	if err != nil || identity != receipt.RootIdentity {
		return scope, SSHPathPin{}, fmt.Errorf("installation root identity changed")
	}
	if err := sshValidateOwned(directory, receipt, reader); err != nil {
		return scope, SSHPathPin{}, err
	}
	task, err := machine.task(ctx, "inspect", receipt.Intent.Task)
	if err != nil || !task.Exists || task.Running || !task.Matches || task.Fingerprint != receipt.TaskFingerprint {
		return scope, SSHPathPin{}, fmt.Errorf("installed task changed or is running: %v", err)
	}
	selected, err := machine.target(receipt.Intent)
	if err != nil {
		return scope, SSHPathPin{}, err
	}
	parent, err := reader.pin(directory, true)
	if err != nil {
		return scope, SSHPathPin{}, err
	}
	scope = SSHInstalledScope{Receipt: image, Root: root, Target: selected, RuntimeFiles: []SSHFilePin{}, TaskFingerprint: task.Fingerprint}
	for _, file := range receipt.Files {
		path := filepath.Join(directory, filepath.FromSlash(file.Path))
		if file.Kind == "directory" {
			pin, err := reader.pin(path, true)
			if err != nil {
				return scope, parent, err
			}
			scope.RuntimeFiles = append(scope.RuntimeFiles, SSHFilePin{Path: pin, BytesSHA: digest(nil)})
		} else {
			image, err := reader.image(path, maxArtifact)
			if err != nil {
				return scope, parent, err
			}
			if image.Pin.BytesSHA != file.SHA256 || image.Pin.Size != file.Size {
				return scope, parent, fmt.Errorf("runtime bytes changed")
			}
			scope.RuntimeFiles = append(scope.RuntimeFiles, image.Pin)
		}
	}
	slices.SortFunc(scope.RuntimeFiles, func(a, b SSHFilePin) int { return strings.Compare(a.Path.Path, b.Path.Path) })
	source := sshSource(parent, receipt.Intent.OwnerSID)
	if err := sshAbsentSource(source, reader); err != nil {
		return scope, parent, err
	}
	return scope, parent, nil
}
func sshReceipt(r SSHPreparationRequest, image SSHByteImage) (installationReceipt, error) {
	var receipt installationReceipt
	expected := filepath.Join(r.StateRoot, "installations", string(r.InstallationID), "receipt.json")
	if !sshImageValid(image, 2<<20) || image.Pin.Path.Path != expected {
		return receipt, fmt.Errorf("invalid installed receipt pin")
	}
	if err := strictjson.Decode(image.Bytes, &receipt); err != nil {
		return receipt, err
	}
	if err := receipt.validate(); err != nil {
		return receipt, err
	}
	if !sshSID.MatchString(receipt.Intent.OwnerSID) || receipt.State != "installed" || receipt.InstallationID != r.InstallationID || receipt.Intent.Root != r.StateRoot || receipt.OperationID == r.OperationID || !strings.EqualFold(receipt.Intent.WindowsUser, r.Account) || receipt.Intent.Task.OwnerSID != receipt.Intent.OwnerSID {
		return receipt, fmt.Errorf("receipt is not the selected installed scope or operation is reused")
	}
	return receipt, nil
}
func sshSource(parent SSHPathPin, sid string) SSHSourceProposal {
	directory := filepath.Join(parent.Path, "ssh-"+sid)
	return SSHSourceProposal{Parent: parent, Directory: directory, File: filepath.Join(directory, "authorized_keys"), Receipt: filepath.Join(directory, "receipt.json"), Pending: filepath.Join(directory, "pending.json"), Stage: filepath.Join(directory, "authorized_keys.stage"), DirectorySDDL: "O:" + sid + "G:" + sid + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + sid + ")", FileSDDL: "O:" + sid + "G:" + sid + "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + sid + ")", InitialBytes: []byte{}}
}
func sshAbsentSource(source SSHSourceProposal, reader sshFilesystem) error {
	entries, err := reader.ReadDir(source.Parent.Path, 256)
	if err != nil {
		return err
	}
	if len(entries) > 256 {
		return fmt.Errorf("excessive installation directory entries")
	}
	for _, entry := range entries {
		if strings.EqualFold(entry.Name(), filepath.Base(source.Directory)) {
			return fmt.Errorf("unowned-collision: proposed SSH directory exists")
		}
	}
	for _, path := range []string{source.Directory, source.File, source.Receipt, source.Pending, source.Stage} {
		if _, err := reader.Stat(path); !os.IsNotExist(err) {
			return fmt.Errorf("unowned-collision: proposed SSH destination is not absent")
		}
	}
	return nil
}

func buildSSHPreparationPlan(r SSHPreparationRequest, observed sshNativeObservation) (SSHPreparationPlan, error) {
	var plan SSHPreparationPlan
	raw, err := json.Marshal(observed)
	if err != nil || len(raw) > maxSSHObservation {
		return plan, fmt.Errorf("observation exceeds bound")
	}
	receipt, err := sshReceipt(r, observed.Installed.Receipt)
	if err != nil {
		return plan, err
	}
	installed := observed.Installed
	sid := receipt.Intent.OwnerSID
	if !sshSID.MatchString(sid) || installed.AccountSID != sid || installed.InteractiveSID != sid || installed.AuthenticatedSID != sid || installed.Root.Path != r.StateRoot || !sshPinValid(installed.Root) || !sshPinValid(observed.Parent) || observed.Parent.Path != filepath.Dir(installed.Receipt.Pin.Path.Path) || installed.TaskFingerprint != receipt.TaskFingerprint {
		return plan, fmt.Errorf("installed account, root or task identity mismatch")
	}
	if len(installed.RuntimeFiles) != len(receipt.Files) {
		return plan, fmt.Errorf("runtime pins incomplete")
	}
	for i, pin := range installed.RuntimeFiles {
		if !sshFileValid(pin) || i > 0 && installed.RuntimeFiles[i-1].Path.Path >= pin.Path.Path {
			return plan, fmt.Errorf("invalid runtime pin order")
		}
	}
	if !sshImageValid(observed.Configuration, maxSSHConfig) || !sshFileValid(observed.Keygen) || !sshFileValid(observed.Service.Binary) {
		return plan, fmt.Errorf("invalid OpenSSH file pins")
	}
	keys, err := sshConfig(observed.Configuration.Bytes)
	if err != nil {
		return plan, err
	}
	service := observed.Service
	if service.InstallationProvenance != "system-directory-openssh-binaries-and-existing-service; capability-inventory-unobserved" || service.Name != "sshd" || service.State != "Running" || service.Account != "LocalSystem" || service.StartType != "Auto" || service.ServiceSDDL == "" || service.OSBuild == "" || !strings.HasPrefix(service.BinaryVersion, "9.5.") {
		return plan, fmt.Errorf("unsupported OpenSSH installation provenance, version or service")
	}
	if service.CommandLine != `"`+service.Binary.Path.Path+`"` || !strings.EqualFold(filepath.Base(service.Binary.Path.Path), "sshd.exe") || filepath.Dir(observed.Keygen.Path.Path) != filepath.Dir(service.Binary.Path.Path) || !strings.EqualFold(filepath.Base(observed.Keygen.Path.Path), "ssh-keygen.exe") {
		return plan, fmt.Errorf("unsupported service command or keygen path")
	}
	if len(observed.HostKeys) != 1 || len(keys) != 1 {
		return plan, fmt.Errorf("one explicit Ed25519 configured host key required")
	}
	key := observed.HostKeys[0]
	if !sshPinValid(key.PrivateSource) || key.PrivateSource.Path != keys[0] || !sshImageValid(key.PublicSource, 16<<10) || key.PublicSource.Pin.Path.Path != key.PrivateSource.Path+".pub" || key.Provenance != "configured-private-key-derived-by-pinned-ssh-keygen; listener-unverified" {
		return plan, fmt.Errorf("invalid configured host-key provenance")
	}
	public, err := sshPublic(key.PublicSource.Bytes)
	if err != nil || public != key.PublicKey || key.PublicSHA != digest([]byte(public)) {
		return plan, fmt.Errorf("configured and companion public keys differ")
	}
	if err := sshFirewall(r.Connection, observed.Firewall, service.Binary.Path.Path); err != nil {
		return plan, err
	}
	if len(observed.Policies) != len(r.ControlAccounts)+1 {
		return plan, fmt.Errorf("selected and independent control policies required")
	}
	source := sshSource(observed.Parent, sid)
	sourceToken := strings.ReplaceAll(source.File, `\`, "/")
	if strings.ContainsAny(sourceToken, " \t\r\n\"'#%") {
		return plan, fmt.Errorf("unsupported owned source token")
	}
	policies := make([]SSHEffectivePolicy, 0, len(observed.Policies))
	seenSID := map[string]bool{}
	var selectedSources []string
	adminControl := false
	for index, current := range observed.Policies {
		account := r.Account
		if index > 0 {
			account = r.ControlAccounts[index-1]
		}
		if current.Account != account || !sshSID.MatchString(current.SID) || seenSID[current.SID] || index == 0 && current.SID != sid {
			return plan, fmt.Errorf("ambiguous account or duplicate control SID")
		}
		if len(current.Groups) > 64 || !sortedUnique(current.Groups) || current.Administrator != slices.Contains(current.Groups, "S-1-5-32-544") {
			return plan, fmt.Errorf("invalid account membership")
		}
		for _, group := range current.Groups {
			if !sshGroupSID.MatchString(group) {
				return plan, fmt.Errorf("invalid group SID")
			}
		}
		if index > 0 && current.Administrator {
			adminControl = true
		}
		seenSID[current.SID] = true
		canonical, values, err := sshPolicy(current.Text)
		if err != nil {
			return plan, err
		}
		if values["port"] != strconv.Itoa(int(r.Connection.Port)) || values["pubkeyauthentication"] != "yes" || values["authorizedkeyscommand"] != "none" || values["authorizedprincipalscommand"] != "none" || values["authorizedprincipalsfile"] != "none" || values["trustedusercakeys"] != "none" || values["hostkey"] != keys[0] {
			return plan, fmt.Errorf("unsupported effective authentication or endpoint policy")
		}
		if err := sshListenAddresses(values["listenaddress"], r.Connection); err != nil {
			return plan, err
		}
		sources := strings.Fields(values["authorizedkeysfile"])
		if len(sources) < 1 || len(sources) > 8 {
			return plan, fmt.Errorf("missing or excessive existing authorization sources")
		}
		unique := map[string]bool{}
		for _, value := range sources {
			if value != ".ssh/authorized_keys" && value != ".ssh/authorized_keys2" || unique[value] {
				return plan, fmt.Errorf("unsupported or duplicate existing authorization source")
			}
			unique[value] = true
		}
		predicted := slices.Clone(current.Text)
		if index == 0 {
			selectedSources = sources
			line := "authorizedkeysfile " + strings.Join(sources, " ")
			predicted = bytes.Replace(canonical, []byte(line+"\n"), []byte(line+" "+sourceToken+"\n"), 1)
		}
		policies = append(policies, SSHEffectivePolicy{Account: current.Account, SID: current.SID, Administrator: current.Administrator, Groups: slices.Clone(current.Groups), NativeBefore: slices.Clone(current.Text), BeforeSHA: digest(current.Text), PredictedAfter: predicted, AfterSHA: digest(predicted), PriorSources: sources, NativeProofRequired: true})
	}
	if observed.Policies[0].Administrator && !adminControl {
		return plan, fmt.Errorf("selected administrator requires an independent administrator control")
	}
	newline := "\n"
	if bytes.Contains(observed.Configuration.Bytes, []byte("\r\n")) {
		newline = "\r\n"
	}
	insertion := ""
	if len(observed.Configuration.Bytes) > 0 && !bytes.HasSuffix(observed.Configuration.Bytes, []byte("\n")) {
		insertion = newline
	}
	insertion += "Match User " + r.Account + newline + "    AuthorizedKeysFile " + strings.Join(selectedSources, " ") + " " + sourceToken + newline + "Match all" + newline
	after := append(slices.Clone(observed.Configuration.Bytes), []byte(insertion)...)
	service.Activation = "restart-existing-service-after-native-postimage-validation"
	service.RequiredPrivilege = "administrator"
	body := SSHPreparationPlanBody{SchemaVersion: 1, Request: r, RequestSHA256: sshDomainDigest("blender-box-ssh-preparation-request-v1\x00", r), Installed: installed, Configuration: SSHConfigurationChange{Before: observed.Configuration, InsertOffset: int64(len(observed.Configuration.Bytes)), InsertBytes: []byte(insertion), AfterBytes: after, AfterSHA: digest(after)}, Source: source, Policies: policies, Service: service, Keygen: observed.Keygen, HostKeys: observed.HostKeys, Firewall: observed.Firewall, FirewallChange: "preserve-existing", ReversalLimit: "A later restart may interrupt connections. Reversal requires exact owned postimage; later operator changes cannot be overwritten. Preview grants no authority and does not guarantee idle admission.", PolicyProof: "native-before/predicted-after; staged native proof required before apply"}
	plan = SSHPreparationPlan{Body: body, PlanSHA256: sshDomainDigest("blender-box-ssh-preparation-plan-v1\x00", body)}
	encoded, err := json.Marshal(plan)
	if err != nil || len(encoded) > 8<<20 {
		return SSHPreparationPlan{}, fmt.Errorf("plan exceeds bound")
	}
	return plan, nil
}
func sshDomainDigest(domain string, value any) SHA256 {
	data, _ := json.Marshal(value)
	return digest(append([]byte(domain), data...))
}
func sshPublic(data []byte) (string, error) {
	if len(data) > 16<<10 || !utf8.Valid(data) {
		return "", fmt.Errorf("invalid public key output")
	}
	text := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if strings.ContainsAny(text, "\r\n\x00") {
		return "", fmt.Errorf("expected exactly one public key")
	}
	fields := strings.Fields(text)
	if len(fields) < 2 {
		return "", fmt.Errorf("public key missing")
	}
	return sshkey.CanonicalPublicKey(fields[0] + " " + fields[1])
}
func sshConfig(data []byte) ([]string, error) {
	if len(data) > maxSSHConfig || !utf8.Valid(data) || bytes.ContainsAny(data, "\x00\v\f") {
		return nil, fmt.Errorf("invalid configuration bytes")
	}
	lf := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	if bytes.ContainsRune(lf, '\r') || bytes.Contains(data, []byte("\r\n")) && bytes.Count(data, []byte("\n")) != bytes.Count(data, []byte("\r\n")) {
		return nil, fmt.Errorf("unsupported mixed line endings")
	}
	allowed := strings.Fields("port addressfamily listenaddress hostkey syslogfacility loglevel logingracetime permitrootlogin strictmodes maxauthtries maxsessions pubkeyauthentication authorizedkeysfile passwordauthentication permitemptypasswords kbdinteractiveauthentication authenticationmethods allowtcpforwarding allowagentforwarding gatewayports x11forwarding permittty printmotd printlastlog tcpkeepalive clientaliveinterval clientalivecountmax usedns pidfile maxstartups permituserrc acceptenv subsystem versionaddendum rekeylimit")
	seen := map[string]bool{}
	keys := []string{}
	for _, line := range strings.Split(string(lf), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsAny(line, "\"'#") {
			return nil, fmt.Errorf("unsupported configuration quoting or continuation")
		}
		fields := strings.Fields(line)
		name := strings.ToLower(fields[0])
		if name != "hostkey" && strings.Contains(line, `\`) {
			return nil, fmt.Errorf("unsupported configuration continuation")
		}
		if name == "include" || name == "match" {
			return nil, fmt.Errorf("unsupported existing %s configuration", name)
		}
		if len(fields) < 2 || !slices.Contains(allowed, name) || seen[name] && name != "listenaddress" && name != "hostkey" && name != "acceptenv" {
			return nil, fmt.Errorf("unsupported or duplicate configuration directive %s", name)
		}
		seen[name] = true
		if name == "hostkey" {
			if len(fields) != 2 {
				return nil, fmt.Errorf("ambiguous HostKey")
			}
			keys = append(keys, fields[1])
		}
	}
	return keys, nil
}
func sshPolicy(data []byte) ([]byte, map[string]string, error) {
	if len(data) == 0 || len(data) > maxSSHConfig || !utf8.Valid(data) || bytes.ContainsAny(data, "\x00\v\f") || !bytes.HasSuffix(data, []byte("\n")) {
		return nil, nil, fmt.Errorf("invalid native policy output")
	}
	lf := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	if bytes.ContainsRune(lf, '\r') || bytes.Contains(data, []byte("\r\n")) && bytes.Count(data, []byte("\n")) != bytes.Count(data, []byte("\r\n")) {
		return nil, nil, fmt.Errorf("unsupported native policy line endings")
	}
	values := map[string]string{}
	keys := []string{}
	lines := strings.Split(strings.TrimSuffix(string(lf), "\n"), "\n")
	if len(lines) > 256 {
		return nil, nil, fmt.Errorf("excessive native policy lines")
	}
	repetitions := map[string]int{}
	for _, line := range lines {
		if len(line) > 8192 {
			return nil, nil, fmt.Errorf("native policy line exceeds bound")
		}
		key, value, ok := strings.Cut(line, " ")
		if !ok || !sshPolicyName.MatchString(key) || strings.TrimSpace(value) != value || value == "" {
			return nil, nil, fmt.Errorf("malformed native policy line")
		}
		repetitions[key]++
		if repetitions[key] > 16 {
			return nil, nil, fmt.Errorf("excessive native policy repetitions")
		}
		if old, exists := values[key]; exists {
			if key != "listenaddress" && key != "hostkey" && key != "acceptenv" {
				return nil, nil, fmt.Errorf("duplicate native policy key %s", key)
			}
			values[key] = old + "\n" + value
		} else {
			keys = append(keys, key)
			values[key] = value
		}
	}
	slices.Sort(keys)
	var out strings.Builder
	for _, key := range keys {
		for _, value := range strings.Split(values[key], "\n") {
			out.WriteString(key + " " + value + "\n")
		}
	}
	return []byte(out.String()), values, nil
}
func sshListenAddresses(value string, c SSHConnectionScope) error {
	actual := []string{}
	for _, address := range strings.Split(value, "\n") {
		endpoint, err := netip.ParseAddrPort(address)
		if err != nil || endpoint.Port() != c.Port {
			return fmt.Errorf("unsupported listener address")
		}
		actual = append(actual, endpoint.Addr().String())
	}
	slices.Sort(actual)
	if !slices.Equal(actual, c.LocalAddresses) {
		return fmt.Errorf("effective listener differs from selected local addresses")
	}
	return nil
}
func sshFirewall(c SSHConnectionScope, rules []SSHFirewallRule, executable string) error {
	if len(rules) == 0 || len(rules) > 256 {
		return fmt.Errorf("explicit existing firewall rule required")
	}
	for i, rule := range rules {
		if rule.ID == "" || i > 0 && rules[i-1].ID >= rule.ID || !rule.Enabled || rule.Direction != "Inbound" || rule.Action != "Allow" || rule.PolicyStore != "PersistentStore" || rule.Protocol != "TCP" || !slices.Equal(rule.Profiles, c.FirewallProfiles) || !slices.Equal(rule.LocalAddresses, c.LocalAddresses) || !slices.Equal(rule.RemoteAddresses, c.RemotePrefixes) || !slices.Equal(rule.LocalPorts, []string{strconv.Itoa(int(c.Port))}) || !slices.Equal(rule.RemotePorts, []string{"Any"}) || rule.Program != "Any" && !strings.EqualFold(rule.Program, executable) || rule.Service != "Any" && rule.Service != "sshd" || !slices.Equal(rule.InterfaceTypes, []string{"Any"}) || rule.EdgeTraversal != "Block" {
			return fmt.Errorf("unsupported overlapping or nonexact firewall rule %s", rule.ID)
		}
	}
	return nil
}
func decodeSSHObservation(data []byte, output any) error {
	if len(data) == 0 || len(data) > 1<<20 || !utf8.Valid(data) {
		return fmt.Errorf("native observation exceeds bounds or is malformed")
	}
	return strictjson.Decode(data, output)
}

func sshValidateOwned(directory string, receipt installationReceipt, reader sshFilesystem) error {
	allowed := map[string]File{}
	for _, file := range receipt.Files {
		allowed[file.Path] = file
	}
	count := 0
	var walk func(string) error
	walk = func(path string) error {
		info, err := reader.Stat(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		expected, exists := allowed[relative]
		count++
		if !exists || count > maxFiles+64 || info.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 || info.IsDir() != (expected.Kind == "directory") {
			return fmt.Errorf("unowned runtime descendant: %s", relative)
		}
		if info.IsDir() {
			entries, err := reader.ReadDir(path, maxFiles+64)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if err := walk(filepath.Join(path, entry.Name())); err != nil {
					return err
				}
			}
		}
		return nil
	}
	runtime := filepath.Join(directory, "runtime")
	if _, err := reader.Stat(runtime); err == nil {
		if err := walk(runtime); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := reader.trusted(directory, receipt.Intent.OwnerSID); err != nil {
		return err
	}
	for _, file := range receipt.Files {
		path := filepath.Join(directory, filepath.FromSlash(file.Path))
		identity, err := reader.identity(path)
		if err != nil || identity != file.Identity {
			return fmt.Errorf("owned file identity changed: %s", file.Path)
		}
		if err := reader.trusted(path, receipt.Intent.OwnerSID); err != nil {
			return err
		}
	}
	return nil
}
