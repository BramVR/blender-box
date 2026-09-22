package linuxruntime

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BramVR/blender-box/internal/linuxtarget"
)

var sessionName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func UnitPath(home, unit string) string { return home + "/.config/systemd/user/" + unit }
func UnitBytes(root, executable, home string, uid uint32, desktop linuxtarget.Desktop) string {
	return "[Unit]\nDescription=Blender Box owned Run launcher\n\n[Service]\nType=exec\nExitType=cgroup\nRemainAfterExit=no\nRestart=no\nKillMode=process\nExecStart=" + executable + " host run-request --state-root " + root + "\nEnvironment=HOME=" + home + "\nEnvironment=DISPLAY=" + desktop.Display + "\nEnvironment=XAUTHORITY=" + desktop.XAuthority + "\nEnvironment=XDG_RUNTIME_DIR=" + linuxtarget.RuntimeDirectory(uid) + "\nEnvironment=DBUS_SESSION_BUS_ADDRESS=unix:path=" + linuxtarget.RuntimeDirectory(uid) + "/bus\n"
}
func systemEnvironment(uid uint32, desktop linuxtarget.Desktop, home string) []string {
	values := linuxtarget.DesktopEnvironment(uid, desktop)
	values["HOME"] = home
	return CleanEnvironment(values)
}
func UserHome(uid uint32) (string, error) {
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "", err
	}
	if err := linuxtarget.ValidateAbsolutePath(account.HomeDir); err != nil {
		return "", err
	}
	return account.HomeDir, nil
}
func CheckPlatform(ctx context.Context, uid uint32, home string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("requires Ubuntu 24.04 GNOME on Xorg")
	}
	if err := linuxtarget.ValidateUID(uid); err != nil {
		return err
	}
	if uint32(os.Getuid()) != uid || os.Geteuid() != os.Getuid() {
		return fmt.Errorf("SSH UID must equal declared desktop UID")
	}
	actual, err := UserHome(uid)
	if err != nil {
		return err
	}
	if actual != home {
		return fmt.Errorf("configured home must match passwd home for desktop UID")
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" && xdg != home+"/.config" {
		return fmt.Errorf("XDG_CONFIG_HOME must match the configured home .config directory")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return fmt.Errorf("Linux requires unified cgroup v2 for Session lifetime")
	}
	group, err := readBounded("/proc/self/cgroup", 64<<10)
	if err != nil || !strings.HasPrefix(string(group), "0::/") {
		return fmt.Errorf("Linux requires unified cgroup v2 for Session lifetime")
	}
	release, err := readBounded("/etc/os-release", 16<<10)
	if err != nil {
		return err
	}
	fields := properties(release)
	if strings.Trim(fields["ID"], `"`) != "ubuntu" || strings.Trim(fields["VERSION_ID"], `"`) != "24.04" {
		return fmt.Errorf("supported Linux distribution is Ubuntu 24.04")
	}
	output, err := execute(ctx, "/usr/bin/systemctl", []string{"--version"}, CleanEnvironment(nil))
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(output), "systemd 255 ") && !strings.HasPrefix(string(output), "systemd 255\n") {
		return fmt.Errorf("supported systemd version is 255")
	}
	return nil
}
func CheckDesktop(ctx context.Context, uid uint32, desktop linuxtarget.Desktop) error {
	if err := desktop.Validate(); err != nil {
		return err
	}
	home, err := UserHome(uid)
	if err != nil {
		return err
	}
	if err := CheckPlatform(ctx, uid, home); err != nil {
		return err
	}
	if err := SafePath(desktop.XAuthority, uid, true); err != nil {
		return fmt.Errorf("Xauthority: %w", err)
	}
	info, err := os.Stat(desktop.XAuthority)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return fmt.Errorf("Xauthority must be a nonempty private regular file")
	}
	if err := SafePath(linuxtarget.RuntimeDirectory(uid), uid, true); err != nil {
		return err
	}
	env := systemEnvironment(uid, desktop, home)
	list, err := execute(ctx, "/usr/bin/loginctl", []string{"list-sessions", "--no-legend", "--no-pager"}, env)
	if err != nil {
		return err
	}
	matches := []map[string]string{}
	for _, line := range strings.Split(string(list), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[1] != strconv.FormatUint(uint64(uid), 10) {
			continue
		}
		if !sessionName.MatchString(fields[0]) {
			return fmt.Errorf("invalid logind Session label")
		}
		output, err := execute(ctx, "/usr/bin/loginctl", []string{"show-session", fields[0], "--no-pager", "-p", "User", "-p", "Active", "-p", "Remote", "-p", "Type", "-p", "Class", "-p", "Desktop", "-p", "Display", "-p", "Seat"}, env)
		if err != nil {
			return err
		}
		session := properties(output)
		if session["Type"] == "x11" || session["Type"] == "wayland" {
			session["ID"] = fields[0]
			matches = append(matches, session)
		}
	}
	if len(matches) != 1 {
		return fmt.Errorf("requires exactly one local graphical login for the SSH UID; found %d", len(matches))
	}
	session := matches[0]
	xorg, err := checkXorg("/proc", session, desktop)
	if err != nil {
		return err
	}
	if err := validateDesktopSession(session, uid, desktop, xorg); err != nil {
		return err
	}
	socket := "/tmp/.X11-unix/X" + strings.TrimPrefix(desktop.Display, ":")
	socketInfo, err := os.Lstat(socket)
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("configured Xorg display socket is unavailable")
	}
	connection, err := net.DialTimeout("unix", socket, 2*time.Second)
	if err != nil {
		return fmt.Errorf("SSH UID cannot access configured Xorg socket: %w", err)
	}
	return connection.Close()
}

type xorgDesktopFacts struct {
	desktop string
	display string
}

func validateDesktopSession(session map[string]string, uid uint32, desktop linuxtarget.Desktop, xorg xorgDesktopFacts) error {
	label, hasDesktop := session["Desktop"]
	display, hasDisplay := session["Display"]
	if !hasDesktop || !hasDisplay {
		return fmt.Errorf("logind desktop inspection is incomplete")
	}
	if label == "" {
		label = xorg.desktop
	}
	if display == "" {
		display = xorg.display
	}
	if session["User"] != strconv.FormatUint(uint64(uid), 10) || session["Active"] != "yes" || session["Remote"] != "no" || session["Type"] != "x11" || session["Class"] != "user" || display != desktop.Display || session["Seat"] != "seat0" || !gnomeDesktop(label) {
		return fmt.Errorf("requires one active local GNOME Xorg session on seat0; Wayland, remote, virtual and ambiguous sessions are unsupported")
	}
	return nil
}

func gnomeDesktop(label string) bool {
	switch strings.ToLower(label) {
	case "gnome", "ubuntu", "ubuntu:gnome", "ubuntu-xorg", "gnome-xorg":
		return true
	}
	return false
}

func checkXorg(procRoot string, session map[string]string, desktop linuxtarget.Desktop) (xorgDesktopFacts, error) {
	facts := xorgDesktopFacts{}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return facts, err
	}
	var matches []struct {
		root     string
		identity xorgProcessIdentity
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		base := filepath.Join(procRoot, entry.Name())
		identity, err := readXorgProcessIdentity(base)
		if err != nil || identity.executable != "/usr/lib/xorg/Xorg" {
			continue
		}
		cmdline, err := readBounded(base+"/cmdline", 64<<10)
		if err != nil {
			continue
		}
		if xorgMatches(session["ID"], identity.cgroup, strings.Split(string(cmdline), "\x00"), desktop) {
			matches = append(matches, struct {
				root     string
				identity xorgProcessIdentity
			}{base, identity})
		}
	}
	if len(matches) != 1 {
		return facts, fmt.Errorf("configured display must belong to exactly one real Xorg process in the active logind session")
	}
	process := matches[0]
	base := process.root
	if session["Desktop"] == "" {
		environ, err := readBounded(base+"/environ", 64<<10)
		if err != nil {
			return facts, fmt.Errorf("read active Xorg desktop metadata: %w", err)
		}
		values := map[string]string{}
		for _, entry := range strings.Split(string(environ), "\x00") {
			if key, value, ok := strings.Cut(entry, "="); ok {
				values[key] = value
			}
		}
		if values["XDG_SESSION_ID"] != session["ID"] || !gnomeDesktop(values["XDG_CURRENT_DESKTOP"]) {
			return facts, fmt.Errorf("active Xorg process must identify the same GNOME logind session")
		}
		for _, key := range []string{"DESKTOP_SESSION", "XDG_SESSION_DESKTOP", "GDMSESSION"} {
			if value := values[key]; value != "" && !gnomeDesktop(value) {
				return facts, fmt.Errorf("active Xorg process has contradictory desktop metadata")
			}
		}
		facts.desktop = values["XDG_CURRENT_DESKTOP"]
	}
	if session["Display"] == "" {
		if err := checkXorgDisplaySocket(procRoot, base, desktop.Display); err != nil {
			return facts, err
		}
		facts.display = desktop.Display
	}
	if err := process.identity.check(base); err != nil {
		return xorgDesktopFacts{}, err
	}
	return facts, nil
}

type xorgProcessIdentity struct {
	startTime  string
	executable string
	cgroup     string
}

func readXorgProcessIdentity(base string) (xorgProcessIdentity, error) {
	identity := xorgProcessIdentity{}
	stat, err := readBounded(base+"/stat", 64<<10)
	if err != nil {
		return identity, err
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return identity, fmt.Errorf("invalid Xorg process stat")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return identity, fmt.Errorf("incomplete Xorg process stat")
	}
	if start, err := strconv.ParseUint(fields[19], 10, 64); err != nil || start == 0 {
		return identity, fmt.Errorf("invalid Xorg process start time")
	}
	identity.startTime = fields[19]
	identity.executable, err = os.Readlink(base + "/exe")
	if err != nil {
		return identity, err
	}
	cgroup, err := readBounded(base+"/cgroup", 64<<10)
	identity.cgroup = string(cgroup)
	return identity, err
}

func (identity xorgProcessIdentity) check(base string) error {
	current, err := readXorgProcessIdentity(base)
	if err != nil || current != identity {
		return fmt.Errorf("active Xorg process identity changed during desktop inspection")
	}
	return nil
}

func checkXorgDisplaySocket(procRoot, processRoot, display string) error {
	sockets, err := readBounded(filepath.Join(procRoot, "net/unix"), 1<<20)
	if err != nil {
		return fmt.Errorf("read Xorg display socket ownership: %w", err)
	}
	path := "/tmp/.X11-unix/X" + strings.TrimPrefix(display, ":")
	var inodes []string
	for _, line := range strings.Split(string(sockets), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 8 && fields[3] == "00010000" && fields[4] == "0001" && fields[5] == "01" && fields[7] == path {
			if inode, err := strconv.ParseUint(fields[6], 10, 64); err == nil && inode != 0 {
				inodes = append(inodes, fields[6])
			}
		}
	}
	if len(inodes) != 1 {
		return fmt.Errorf("configured display must have exactly one listening Unix socket")
	}
	fds, err := os.ReadDir(processRoot + "/fd")
	if err != nil {
		return fmt.Errorf("read active Xorg socket descriptors: %w", err)
	}
	for _, fd := range fds {
		link, err := os.Readlink(processRoot + "/fd/" + fd.Name())
		if err == nil && link == "socket:["+inodes[0]+"]" {
			return nil
		}
	}
	return fmt.Errorf("configured display listener must belong to the active Xorg process")
}
func properties(output []byte) map[string]string {
	result := map[string]string{}
	for _, line := range strings.Split(string(output), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			result[key] = value
		}
	}
	return result
}

func CheckUnit(ctx context.Context, root, executable, home, unit string, uid uint32, desktop linuxtarget.Desktop) (string, error) {
	if err := linuxtarget.ValidateUnitName(unit); err != nil {
		return "", err
	}
	unitPath := UnitPath(home, unit)
	if err := SafePath(unitPath, uid, true); err != nil {
		return "", err
	}
	contents, err := readBounded(unitPath, 16<<10)
	if err != nil {
		return "", err
	}
	if string(contents) != UnitBytes(root, executable, home, uid, desktop) {
		return "", fmt.Errorf("static Linux unit bytes do not match configured host, root and desktop; run explicit setup")
	}
	env := systemEnvironment(uid, desktop, home)
	args := []string{"--user", "show", unit, "--no-pager"}
	names := []string{"LoadState", "ActiveState", "SubState", "FragmentPath", "DropInPaths", "Names", "Type", "ExitType", "RemainAfterExit", "Restart", "KillMode", "ExecStart", "ExecStartPre", "ExecStartPost", "ExecCondition", "ExecStop", "ExecStopPost", "EnvironmentFiles", "Environment", "PartOf", "Requires", "Wants", "BindsTo", "UnitFileState", "NeedDaemonReload", "Slice"}
	for _, name := range names {
		args = append(args, "-p", name)
	}
	output, err := execute(ctx, "/usr/bin/systemctl", args, env)
	if err != nil {
		return "", err
	}
	facts := properties(output)
	if err := validateUnitFacts(facts, root, executable, home, unit, uid, desktop); err != nil {
		return "", err
	}
	return facts["ActiveState"], nil
}
func validateUnitFacts(facts map[string]string, root, executable, home, unit string, uid uint32, desktop linuxtarget.Desktop) error {
	expected := map[string]string{"LoadState": "loaded", "FragmentPath": UnitPath(home, unit), "Names": unit, "Type": "exec", "ExitType": "cgroup", "RemainAfterExit": "no", "Restart": "no", "KillMode": "process", "NeedDaemonReload": "no", "Slice": "app.slice"}
	deps := strings.Fields(facts["Requires"])
	sort.Strings(deps)
	if strings.Join(deps, " ") != "app.slice basic.target" {
		return fmt.Errorf("Linux unit effective Requires mismatch")
	}
	for key, want := range expected {
		if facts[key] != want {
			return fmt.Errorf("Linux unit effective %s mismatch", key)
		}
	}
	for _, key := range []string{"DropInPaths", "PartOf", "Wants", "BindsTo"} {
		if value, exists := facts[key]; !exists || value != "" {
			return fmt.Errorf("Linux unit effective %s must be empty", key)
		}
	}
	// systemd 255 omits empty struct arrays even with show --all.
	for _, key := range []string{"EnvironmentFiles", "ExecStartPre", "ExecStartPost", "ExecCondition", "ExecStop", "ExecStopPost"} {
		if facts[key] != "" {
			return fmt.Errorf("Linux unit effective %s must be empty", key)
		}
	}
	if facts["UnitFileState"] != "static" {
		return fmt.Errorf("Linux unit must be static without enablement or aliases")
	}
	wantArgs := executable + " host run-request --state-root " + root
	start := facts["ExecStart"]
	if !strings.HasPrefix(start, "{ path="+executable+" ; argv[]="+wantArgs+" ; ignore_errors=no ; ") || strings.Count(start, "{ path=") != 1 {
		return fmt.Errorf("Linux unit effective ExecStart mismatch")
	}
	values := map[string]bool{}
	for _, value := range strings.Fields(facts["Environment"]) {
		values[value] = true
	}
	expectedEnv := linuxtarget.DesktopEnvironment(uid, desktop)
	expectedEnv["HOME"] = home
	if len(values) != len(expectedEnv) {
		return fmt.Errorf("Linux unit effective environment mismatch")
	}
	for key, value := range expectedEnv {
		if !values[key+"="+value] {
			return fmt.Errorf("Linux unit effective environment mismatch")
		}
	}
	switch facts["ActiveState"] {
	case "inactive", "active", "activating", "deactivating", "failed":
	default:
		return fmt.Errorf("Linux unit has unknown activity state")
	}
	return nil
}
func Launch(ctx context.Context, root, unit string, uid uint32, desktop linuxtarget.Desktop) error {
	home, err := UserHome(uid)
	if err != nil {
		return err
	}
	if err := CheckDesktop(ctx, uid, desktop); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable = filepath.Clean(executable)
	if err := SafePath(executable, uid, false); err != nil {
		return err
	}
	state, err := CheckUnit(ctx, root, executable, home, unit, uid, desktop)
	if err != nil {
		return err
	}
	if state == "active" || state == "activating" {
		return nil
	}
	if state != "inactive" {
		return UnitUnavailable(state)
	}
	_, err = execute(ctx, "/usr/bin/systemctl", []string{"--user", "start", unit}, systemEnvironment(uid, desktop, home))
	return err
}

func Prepare(ctx context.Context, root, unit string, uid uint32, desktop linuxtarget.Desktop) error {
	home, err := UserHome(uid)
	if err != nil {
		return err
	}
	if err := CheckDesktop(ctx, uid, desktop); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	state, err := CheckUnit(ctx, root, executable, home, unit, uid, desktop)
	if err != nil {
		return err
	}
	if state != "inactive" {
		return UnitUnavailable(state)
	}
	return nil
}
func CheckExecutionContext(unit string) error {
	if err := linuxtarget.ValidateUnitName(unit); err != nil {
		return err
	}
	group, err := readBounded("/proc/self/cgroup", 64<<10)
	if err != nil {
		return err
	}
	if !strings.HasSuffix(strings.TrimSpace(string(group)), "/app.slice/"+unit) {
		return fmt.Errorf("Linux run-request must execute inside its configured static user service")
	}
	return nil
}

func xorgMatches(session, cgroup string, args []string, desktop linuxtarget.Desktop) bool {
	if !strings.Contains(strings.TrimSpace(cgroup)+"/", "/session-"+session+".scope/") {
		return false
	}
	displayOK, authOK := false, false
	for i, arg := range args {
		if strings.HasPrefix(arg, ":") && arg != desktop.Display {
			return false
		}
		if arg == desktop.Display {
			displayOK = true
		}
		if arg == "-displayfd" && i+1 < len(args) {
			if fd, err := strconv.Atoi(args[i+1]); err == nil && fd >= 0 {
				displayOK = true
			}
		}
		if arg == "-auth" && i+1 < len(args) && args[i+1] == desktop.XAuthority {
			authOK = true
		}
	}
	return displayOK && authOK
}
func UnitUnavailable(state string) error {
	if state == "failed" {
		return fmt.Errorf("Linux service failed; establish exact Session cleanup, then have the operator inspect and reset the exact setup-owned failed unit before retrying")
	}
	return fmt.Errorf("Linux service is %s; wait for prior exact Session settlement and retry this Run", state)
}
