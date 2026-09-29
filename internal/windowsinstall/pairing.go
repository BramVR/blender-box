package windowsinstall

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BramVR/blender-box/internal/pairing"
)

// adminKeysSDDL is the protected descriptor Windows sshd requires on administrators_authorized_keys
// and the only descriptor ReplaceKeys ever creates.
const adminKeysSDDL = `O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)`
const defaultAdminKeysFile = `C:\ProgramData\ssh\administrators_authorized_keys`

const (
	sidSystem         = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
)

// keysObservation is one look at an authorized keys file. SHA covers the bytes at observation time
// so a caller that reads the bytes separately can prove both views agree. SDDL is raw for policy
// checks; Security is the Canonical-Security form for equality.
type keysObservation struct {
	Exists   bool   `json:"exists"`
	Reparse  bool   `json:"reparse"`
	Regular  bool   `json:"regular"`
	Size     int64  `json:"size"`
	SHA      string `json:"sha"`
	SDDL     string `json:"sddl"`
	Security string `json:"canonical"`
	Owner    string `json:"owner"`
	Bytes    []byte `json:"-"`
}

// keysReplacement is one compare-and-swap of a keys file. NewSecurity is the raw SDDL for a file
// that does not exist yet; an existing file keeps its own descriptor.
type keysReplacement struct {
	Path             string `json:"path"`
	Exists           bool   `json:"exists"`
	ExpectedSHA      string `json:"expected_sha"`
	ExpectedSecurity string `json:"expected_security"`
	NewSecurity      string `json:"new_security"`
	Contents         []byte `json:"contents_b64"`
}
type keysStore interface {
	read(ctx context.Context, path string) (keysObservation, error)
	// replace writes Contents only while the live file still matches ExpectedSHA and
	// ExpectedSecurity, atomically, and returns the file as re-read afterwards. A compare failure
	// wraps pairing.ErrKeysChanged.
	replace(ctx context.Context, r keysReplacement) (keysObservation, error)
}

func NewPairingPlatform() pairing.Platform {
	return pairingPlatform{machine: nativeMachine{}, sshd: nativeSSHD{}, keys: nativeKeys{}, adminKeysFile: adminKeysFile()}
}

type pairingPlatform struct {
	machine       machine
	sshd          sshdResolver
	keys          keysStore
	adminKeysFile string
}

func (p pairingPlatform) Authority(ctx context.Context, root, installationID string) (pairing.Authority, error) {
	if !installID.MatchString(installationID) {
		return pairing.Authority{}, fmt.Errorf("invalid installation id")
	}
	receipt, err := readReceipt(filepath.Join(root, "installations", installationID, "receipt.json"))
	if err != nil {
		return pairing.Authority{}, fmt.Errorf("installation %s: %w", installationID, err)
	}
	facts, err := p.sshd.facts(ctx, receipt.Intent.WindowsUser, "localhost", "127.0.0.1")
	if err != nil {
		return pairing.Authority{}, err
	}
	if !facts.Elevated {
		return pairing.Authority{}, fmt.Errorf("host pairing needs elevation; run from an elevated PowerShell on the host, or over your admin SSH channel")
	}
	if receipt.State != "installed" {
		return pairing.Authority{}, fmt.Errorf("installation %s is %s, not installed", installationID, receipt.State)
	}
	inspection, err := p.machine.inspect(ctx, Request{Operation: "status", StateRoot: root, WindowsUser: receipt.Intent.WindowsUser})
	if err != nil {
		return pairing.Authority{}, err
	}
	if inspection.OwnerSID != receipt.Intent.OwnerSID || inspection.RootIdentity != receipt.RootIdentity {
		return pairing.Authority{}, fmt.Errorf("installation %s no longer matches this account or state root; re-run setup install", installationID)
	}
	installed, err := p.machine.target(receipt.Intent)
	if err != nil {
		return pairing.Authority{}, err
	}
	if facts.ServiceStatus != "Running" {
		return pairing.Authority{}, fmt.Errorf("sshd is %s; run `blender-box setup ssh` first", facts.ServiceStatus)
	}
	if !facts.PubkeyAuthentication {
		return pairing.Authority{}, fmt.Errorf("sshd disables PubkeyAuthentication for %s; `blender-box setup ssh` reports the change it needs", receipt.Intent.WindowsUser)
	}
	return pairing.Authority{
		Installed:       installed,
		InstallationID:  installationID,
		RootIdentity:    receipt.RootIdentity,
		AccountIdentity: inspection.OwnerSID,
		Login:           receipt.Intent.WindowsUser,
		Port:            facts.Port,
		HostPublicKey:   facts.HostKeyEd25519,
		KeysFile:        facts.AuthorizedKeysFile,
		SharedKeysFile:  p.descriptorKind(facts.AuthorizedKeysFile) == "admin",
	}, nil
}

func (p pairingPlatform) descriptorKind(path string) string {
	if strings.EqualFold(path, p.adminKeysFile) {
		return "admin"
	}
	return "user"
}

func (p pairingPlatform) ReadKeys(ctx context.Context, path string) (pairing.KeysFile, error) {
	observed, err := p.keys.read(ctx, path)
	if err != nil {
		return pairing.KeysFile{}, err
	}
	if !observed.Exists {
		return pairing.KeysFile{Path: path, Bytes: []byte{}, SHA: string(digest(nil))}, nil
	}
	if observed.Reparse || !observed.Regular {
		return pairing.KeysFile{}, fmt.Errorf("%s is not a regular file", path)
	}
	if observed.Size > pairing.MaxKeysFile || len(observed.Bytes) > pairing.MaxKeysFile {
		return pairing.KeysFile{}, fmt.Errorf("%s exceeds %d bytes", path, pairing.MaxKeysFile)
	}
	if string(digest(observed.Bytes)) != observed.SHA {
		return pairing.KeysFile{}, fmt.Errorf("%s changed while it was being read", path)
	}
	if err := verifyDescriptor(observed.SDDL, p.descriptorKind(path), observed.Owner); err != nil {
		return pairing.KeysFile{}, fmt.Errorf("%s has a security descriptor sshd rejects (%v); fix its owner or ACL yourself, Blender Box never changes it", path, err)
	}
	return pairing.KeysFile{Path: path, Exists: true, Bytes: observed.Bytes, SHA: observed.SHA, Security: observed.Security}, nil
}

func (p pairingPlatform) ReplaceKeys(ctx context.Context, file pairing.KeysFile, contents []byte) error {
	if len(contents) > pairing.MaxKeysFile {
		return fmt.Errorf("%s would exceed %d bytes", file.Path, pairing.MaxKeysFile)
	}
	kind := p.descriptorKind(file.Path)
	request := keysReplacement{Path: file.Path, Exists: file.Exists, ExpectedSHA: file.SHA, ExpectedSecurity: file.Security, Contents: contents}
	if !file.Exists {
		if kind != "admin" {
			return fmt.Errorf("%s does not exist; create it as the account first", file.Path)
		}
		request.NewSecurity = adminKeysSDDL
	}
	observed, err := p.keys.replace(ctx, request)
	if err != nil {
		return err
	}
	if observed.SHA != string(digest(contents)) {
		return fmt.Errorf("%s does not hold the written bytes after replace", file.Path)
	}
	if file.Exists {
		if observed.Security != file.Security {
			return fmt.Errorf("%s security changed during replace; fix its ACL yourself, Blender Box never changes it", file.Path)
		}
		return nil
	}
	if err := verifyDescriptor(observed.SDDL, kind, observed.Owner); err != nil {
		return fmt.Errorf("%s was created with a security descriptor sshd rejects (%v); fix its ACL yourself", file.Path, err)
	}
	return nil
}

// sidAliases are the SDDL abbreviations Windows prints for well-known principals. An abbreviation
// outside this table fails closed; domain-relative aliases (DA, DU, ...) are deliberately absent.
var sidAliases = map[string]string{
	"AC": "S-1-15-2-1", "AN": "S-1-5-7", "AU": "S-1-5-11", "BA": sidAdministrators, "BG": "S-1-5-32-546",
	"BO": "S-1-5-32-551", "BU": "S-1-5-32-545", "CG": "S-1-3-1", "CO": "S-1-3-0", "IU": "S-1-5-4",
	"LS": "S-1-5-19", "NS": "S-1-5-20", "NU": "S-1-5-2", "OW": "S-1-3-4", "PU": "S-1-5-32-547",
	"RC": "S-1-5-12", "RD": "S-1-5-32-555", "RE": "S-1-5-32-552", "RU": "S-1-5-32-554", "SO": "S-1-5-32-549",
	"SU": "S-1-5-6", "SY": sidSystem, "WD": "S-1-1-0",
}
var accessRights = map[string]uint32{
	"GA": 0x10000000, "GX": 0x20000000, "GW": 0x40000000, "GR": 0x80000000,
	"FA": 0x001f01ff, "FR": 0x00120089, "FW": 0x00120116, "FX": 0x001200a0,
	"SD": 0x00010000, "RC": 0x00020000, "WD": 0x00040000, "WO": 0x00080000,
	"CC": 0x1, "DC": 0x2, "LC": 0x4, "SW": 0x8, "RP": 0x10, "WP": 0x20, "DT": 0x40, "LO": 0x80, "CR": 0x100,
}

// writeRights are the generic write and all bits plus Assert-TrustedItem's authority mask: write
// data, append, write EA, delete child, write attributes, delete, write DAC and write owner.
const writeRights uint32 = 0x40000000 | 0x10000000 | 0x000d0156

type accessEntry struct {
	Allow  bool
	Rights uint32
	SID    string
}
type securityDescriptor struct {
	Owner     string
	Protected bool
	Entries   []accessEntry
}

// verifyDescriptor decides whether sshd would accept an authorized keys file with this descriptor.
// "admin" is the shared administrators file: owner SYSTEM or Administrators, protected DACL, and
// nothing but Allow entries for those two. "user" is an account file: owner SYSTEM, Administrators
// or sid, and no Allow entry that lets anyone else write. Every entry counts, inherited ones too.
func verifyDescriptor(sddl, kind, sid string) error {
	descriptor, err := parseSDDL(sddl)
	if err != nil {
		return err
	}
	trusted := map[string]bool{sidSystem: true, sidAdministrators: true}
	switch kind {
	case "admin":
	case "user":
		if sid == "" {
			return fmt.Errorf("account SID required for a per-user keys file")
		}
		trusted[strings.ToUpper(sid)] = true
	default:
		return fmt.Errorf("unknown descriptor kind %q", kind)
	}
	if !trusted[descriptor.Owner] {
		return fmt.Errorf("owner %s is not trusted", descriptor.Owner)
	}
	if kind == "admin" && !descriptor.Protected {
		return fmt.Errorf("DACL inherits from the directory; it must be protected")
	}
	for _, entry := range descriptor.Entries {
		if kind == "admin" && (!entry.Allow || !trusted[entry.SID]) {
			return fmt.Errorf("access entry for %s; only SYSTEM and Administrators may appear", entry.SID)
		}
		if entry.Allow && entry.Rights&writeRights != 0 && !trusted[entry.SID] {
			return fmt.Errorf("%s can write the file", entry.SID)
		}
	}
	return nil
}

func parseSDDL(sddl string) (securityDescriptor, error) {
	sections := map[byte]string{}
	depth, start := 0, 0
	var key byte
	for i := 0; i < len(sddl); i++ {
		switch c := sddl[i]; {
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth < 0 {
				return securityDescriptor{}, fmt.Errorf("unbalanced security descriptor")
			}
		case depth == 0 && i+1 < len(sddl) && sddl[i+1] == ':' && strings.IndexByte("OGDS", c) >= 0:
			if key != 0 {
				sections[key] = sddl[start:i]
			}
			if _, duplicate := sections[c]; duplicate {
				return securityDescriptor{}, fmt.Errorf("duplicate %c: section in security descriptor", c)
			}
			key, start = c, i+2
			i++
		}
	}
	if depth != 0 {
		return securityDescriptor{}, fmt.Errorf("unbalanced security descriptor")
	}
	if key != 0 {
		sections[key] = sddl[start:]
	}
	if sections['O'] == "" {
		return securityDescriptor{}, fmt.Errorf("security descriptor has no owner")
	}
	owner, err := resolveSID(sections['O'])
	if err != nil {
		return securityDescriptor{}, err
	}
	dacl, ok := sections['D']
	if !ok {
		return securityDescriptor{}, fmt.Errorf("security descriptor has no DACL")
	}
	descriptor := securityDescriptor{Owner: owner}
	flags := dacl
	if open := strings.IndexByte(dacl, '('); open >= 0 {
		flags, dacl = dacl[:open], dacl[open:]
	} else {
		dacl = ""
	}
	for flags != "" {
		switch {
		case flags[0] == 'P':
			descriptor.Protected = true
			flags = flags[1:]
		case strings.HasPrefix(flags, "AI"), strings.HasPrefix(flags, "AR"):
			flags = flags[2:]
		default:
			return securityDescriptor{}, fmt.Errorf("unsupported DACL flags %q", flags)
		}
	}
	for dacl != "" {
		end := strings.IndexByte(dacl, ')')
		if dacl[0] != '(' || end < 0 {
			return securityDescriptor{}, fmt.Errorf("malformed access entry %q", dacl)
		}
		fields := strings.Split(dacl[1:end], ";")
		if len(fields) != 6 {
			return securityDescriptor{}, fmt.Errorf("malformed access entry %q", dacl[:end+1])
		}
		entry := accessEntry{}
		switch fields[0] {
		case "A":
			entry.Allow = true
		case "D":
		default:
			return securityDescriptor{}, fmt.Errorf("unsupported access entry type %q", fields[0])
		}
		if entry.Rights, err = parseRights(fields[2]); err != nil {
			return securityDescriptor{}, err
		}
		if entry.SID, err = resolveSID(fields[5]); err != nil {
			return securityDescriptor{}, err
		}
		descriptor.Entries = append(descriptor.Entries, entry)
		dacl = dacl[end+1:]
	}
	return descriptor, nil
}

func parseRights(text string) (uint32, error) {
	if len(text) > 2 && strings.EqualFold(text[:2], "0x") {
		mask, err := strconv.ParseUint(text[2:], 16, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid access mask %q", text)
		}
		return uint32(mask), nil
	}
	var mask uint32
	for ; len(text) >= 2; text = text[2:] {
		bits, ok := accessRights[text[:2]]
		if !ok {
			return 0, fmt.Errorf("unsupported access right %q", text[:2])
		}
		mask |= bits
	}
	if text != "" {
		return 0, fmt.Errorf("malformed access rights %q", text)
	}
	return mask, nil
}

func resolveSID(text string) (string, error) {
	if upper := strings.ToUpper(text); len(upper) > 4 && strings.HasPrefix(upper, "S-1-") && strings.Trim(upper[4:], "0123456789-") == "" {
		return upper, nil
	}
	if sid, ok := sidAliases[text]; ok {
		return sid, nil
	}
	return "", fmt.Errorf("unsupported SID %q", text)
}
