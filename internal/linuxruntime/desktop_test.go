package linuxruntime

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/BramVR/blender-box/internal/linuxtarget"
)

func TestSystemd255DefaultUserUnitAndDrift(t *testing.T) {
	desktop := linuxtarget.Desktop{Display: ":0", XAuthority: "/run/user/1000/gdm/Xauthority"}
	fixture := `LoadState=loaded
ActiveState=inactive
SubState=dead
FragmentPath=/home/operator/.config/systemd/user/blender-box.service
DropInPaths=
Names=blender-box.service
Type=exec
ExitType=cgroup
RemainAfterExit=no
Restart=no
KillMode=process
UMask=0077
ExecStart={ path=/home/operator/box/bin/blender-box ; argv[]=/home/operator/box/bin/blender-box host run-request --state-root /home/operator/box ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
ExecStartPre=
ExecStartPost=
ExecCondition=
ExecStop=
ExecStopPost=
EnvironmentFiles=
Environment=HOME=/home/operator DISPLAY=:0 XAUTHORITY=/run/user/1000/gdm/Xauthority XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
PartOf=
Requires=basic.target app.slice
Wants=
BindsTo=
UnitFileState=static
NeedDaemonReload=no
Slice=app.slice
`
	validate := func(facts map[string]string) error {
		return validateUnitFacts(facts, "/home/operator/box", "/home/operator/box/bin/blender-box", "/home/operator", "blender-box.service", 1000, desktop)
	}
	if err := validate(properties([]byte(fixture))); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"UMask": "0002", "Requires": "basic.target app.slice other.service", "DropInPaths": "/home/operator/override.conf", "EnvironmentFiles": "/home/operator/.profile", "ExitType": "main", "KillMode": "control-group", "Restart": "always", "PartOf": "graphical-session.target", "Slice": "session.slice", "FragmentPath": "/tmp/foreign.service", "NeedDaemonReload": "yes", "ExecStop": "/usr/bin/killall blender"} {
		t.Run(key, func(t *testing.T) {
			facts := properties([]byte(fixture))
			facts[key] = value
			if err := validate(facts); err == nil {
				t.Fatalf("accepted effective %s drift", key)
			}
		})
	}
	specialArrays := []string{"EnvironmentFiles", "ExecStartPre", "ExecStartPost", "ExecCondition", "ExecStop", "ExecStopPost"}
	for _, key := range specialArrays {
		t.Run(key+" omitted when empty", func(t *testing.T) {
			facts := properties([]byte(fixture))
			delete(facts, key)
			if err := validate(facts); err != nil {
				t.Fatalf("rejected empty systemd 255 array %s: %v", key, err)
			}
		})
		t.Run(key+" populated", func(t *testing.T) {
			facts := properties([]byte(fixture))
			facts[key] = "/home/operator/unexpected"
			if err := validate(facts); err == nil {
				t.Fatalf("accepted populated %s", key)
			}
		})
	}
	facts := properties([]byte(fixture))
	for _, key := range specialArrays {
		delete(facts, key)
	}
	if err := validate(facts); err != nil {
		t.Fatalf("rejected native systemd 255 empty-array output: %v", err)
	}
	for _, key := range []string{"UMask", "DropInPaths", "PartOf", "Wants", "BindsTo", "ExecStart", "LoadState", "FragmentPath", "Names", "Type", "ExitType", "RemainAfterExit", "Restart", "KillMode", "NeedDaemonReload", "Slice", "Requires", "UnitFileState", "Environment"} {
		t.Run(key+" missing", func(t *testing.T) {
			facts := properties([]byte(fixture))
			delete(facts, key)
			if err := validate(facts); err == nil {
				t.Fatalf("accepted incomplete unit inspection without %s", key)
			}
		})
	}
}
func TestGDMDisplayFDAndExactSessionXorgBinding(t *testing.T) {
	desktop := linuxtarget.Desktop{Display: ":0", XAuthority: "/run/user/1000/gdm/Xauthority"}
	args := []string{"/usr/lib/xorg/Xorg", "vt2", "-displayfd", "3", "-auth", desktop.XAuthority, "-nolisten", "tcp", "-background", "none", "-noreset", "-keeptty", "-novtswitch", "-verbose", "3"}
	if !xorgMatches("4", "0::/user.slice/user-1000.slice/session-4.scope\n", args, desktop) {
		t.Fatal("normal GDM Xorg rejected")
	}
	if xorgMatches("4", "0::/user.slice/user-1000.slice/session-40.scope\n", args, desktop) {
		t.Fatal("another logind session accepted")
	}
	if xorgMatches("4", "0::/session-4.scope\n", append(args, ":1"), desktop) {
		t.Fatal("mismatched display accepted")
	}
	args[5] = "/run/user/2000/gdm/Xauthority"
	if xorgMatches("4", "0::/session-4.scope\n", args, desktop) {
		t.Fatal("foreign Xauthority accepted")
	}
}
func TestDesktopExplicitXorgSessionLabels(t *testing.T) {
	desktop := linuxtarget.Desktop{Display: ":0", XAuthority: "/run/user/1000/gdm/Xauthority"}
	for _, label := range []string{"ubuntu-xorg", "gnome-xorg"} {
		for _, protocol := range []string{"x11", "wayland"} {
			t.Run(label+"/"+protocol, func(t *testing.T) {
				fields := properties([]byte("User=1000\nActive=yes\nRemote=no\nType=" + protocol + "\nClass=user\nDesktop=" + label + "\nDisplay=:0\nSeat=seat0\n"))
				err := validateDesktopSession(fields, 1000, desktop, xorgDesktopFacts{})
				if protocol == "x11" && err != nil {
					t.Fatalf("explicit Xorg session label rejected: %v", err)
				}
				if protocol == "wayland" && err == nil {
					t.Fatal("explicit Xorg session label bypassed Wayland refusal")
				}
			})
		}
	}
}

func TestDesktopRejectsUnsupportedSessionFacts(t *testing.T) {
	desktop := linuxtarget.Desktop{Display: ":0", XAuthority: "/run/user/1000/gdm/Xauthority"}
	fields := properties([]byte("User=1000\nActive=yes\nRemote=no\nType=x11\nClass=user\nDesktop=ubuntu\nDisplay=:0\nSeat=seat0\n"))
	if err := validateDesktopSession(fields, 1000, desktop, xorgDesktopFacts{}); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"User": "2000", "Active": "no", "Remote": "yes", "Type": "wayland", "Class": "greeter", "Desktop": "XFCE", "Display": ":1", "Seat": ""} {
		original := fields[key]
		fields[key] = value
		if err := validateDesktopSession(fields, 1000, desktop, xorgDesktopFacts{}); err == nil {
			t.Fatalf("accepted %s=%s", key, value)
		}
		fields[key] = original
	}
	if !strings.Contains(UnitUnavailable("failed").Error(), "operator inspect and reset") {
		t.Fatal("failed unit requires explicit operator recovery")
	}
}

func TestGDMDesktopMetadataFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux /proc symlink contract")
	}
	desktop := linuxtarget.Desktop{Display: ":0", XAuthority: "/run/user/1000/gdm/Xauthority"}
	environ := "DESKTOP_SESSION=gnome\x00XDG_SESSION_ID=4\x00XDG_CURRENT_DESKTOP=GNOME\x00XDG_SESSION_DESKTOP=gnome\x00GDMSESSION=gnome\x00"
	socket := "0000000000000000: 00000002 00000000 00010000 0001 01 12345 /tmp/.X11-unix/X0\n"
	for _, tc := range []struct {
		name           string
		changes        map[string]string
		remove         string
		sessionChanges map[string]string
		removeSession  string
		wantErr        bool
	}{
		{name: "blank GDM metadata"},
		{name: "populated logind metadata needs no fallback", sessionChanges: map[string]string{"Desktop": "ubuntu", "Display": ":0"}, changes: map[string]string{"42/environ": "unreadable metadata", "net/unix": "unavailable table"}},
		{name: "only desktop missing", sessionChanges: map[string]string{"Display": ":0"}, remove: "net/unix"},
		{name: "only display missing", sessionChanges: map[string]string{"Desktop": "ubuntu"}, remove: "42/environ"},
		{name: "missing logind Desktop key", removeSession: "Desktop", wantErr: true},
		{name: "missing logind Display key", removeSession: "Display", wantErr: true},
		{name: "oversized process environment", changes: map[string]string{"42/environ": environ + strings.Repeat("x", 64<<10)}, wantErr: true},
		{name: "malformed process identity", changes: map[string]string{"42/stat": "42 (Xorg) S"}, wantErr: true},
		{name: "missing process environment", remove: "42/environ", wantErr: true},
		{name: "missing session identity", changes: map[string]string{"42/environ": strings.ReplaceAll(environ, "XDG_SESSION_ID=4\x00", "")}, wantErr: true},
		{name: "foreign session identity", changes: map[string]string{"42/environ": strings.ReplaceAll(environ, "XDG_SESSION_ID=4", "XDG_SESSION_ID=40")}, wantErr: true},
		{name: "missing GNOME identity", changes: map[string]string{"42/environ": "XDG_SESSION_ID=4\x00"}, wantErr: true},
		{name: "foreign desktop", changes: map[string]string{"42/environ": strings.ReplaceAll(environ, "XDG_CURRENT_DESKTOP=GNOME", "XDG_CURRENT_DESKTOP=XFCE")}, wantErr: true},
		{name: "contradictory desktop", changes: map[string]string{"42/environ": strings.ReplaceAll(environ, "GDMSESSION=gnome", "GDMSESSION=xfce")}, wantErr: true},
		{name: "foreign cgroup", changes: map[string]string{"42/cgroup": "0::/user.slice/user-1000.slice/session-40.scope\n"}, wantErr: true},
		{name: "foreign Xauthority", changes: map[string]string{"42/cmdline": "/usr/lib/xorg/Xorg\x00-displayfd\x003\x00-auth\x00/foreign/Xauthority\x00"}, wantErr: true},
		{name: "foreign executable", changes: map[string]string{"42/exe": "/usr/bin/Xvfb"}, wantErr: true},
		{name: "foreign socket", changes: map[string]string{"net/unix": strings.ReplaceAll(socket, "X0", "X1")}, wantErr: true},
		{name: "abstract socket only", changes: map[string]string{"net/unix": strings.ReplaceAll(socket, "/tmp/", "@/tmp/")}, wantErr: true},
		{name: "non-listening socket", changes: map[string]string{"net/unix": strings.ReplaceAll(socket, "00010000", "00000000")}, wantErr: true},
		{name: "datagram socket", changes: map[string]string{"net/unix": strings.ReplaceAll(socket, "0001 01", "0002 01")}, wantErr: true},
		{name: "connected socket", changes: map[string]string{"net/unix": strings.ReplaceAll(socket, "0001 01", "0001 03")}, wantErr: true},
		{name: "ambiguous sockets", changes: map[string]string{"net/unix": socket + strings.ReplaceAll(socket, "12345", "54321")}, wantErr: true},
		{name: "foreign socket owner", changes: map[string]string{"42/fd/7": "socket:[54321]"}, wantErr: true},
		{name: "missing descriptors", remove: "42/fd/7", wantErr: true},
		{name: "missing socket table", remove: "net/unix", wantErr: true},
		{name: "duplicate Xorg", changes: map[string]string{
			"43/exe":     "/usr/lib/xorg/Xorg",
			"43/stat":    xorgStatFixture,
			"43/cgroup":  "0::/user.slice/user-1000.slice/session-4.scope\n",
			"43/cmdline": "/usr/lib/xorg/Xorg\x00-displayfd\x003\x00-auth\x00" + desktop.XAuthority + "\x00",
		}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{
				"42/exe":     "/usr/lib/xorg/Xorg",
				"42/stat":    xorgStatFixture,
				"42/cgroup":  "0::/user.slice/user-1000.slice/session-4.scope\n",
				"42/cmdline": "/usr/lib/xorg/Xorg\x00vt2\x00-displayfd\x003\x00-auth\x00" + desktop.XAuthority + "\x00-nolisten\x00tcp\x00",
				"42/environ": environ,
				"42/fd/7":    "socket:[12345]",
				"net/unix":   socket,
			}
			for name, value := range tc.changes {
				files[name] = value
			}
			delete(files, tc.remove)
			procRoot := t.TempDir()
			for name, value := range files {
				path := filepath.Join(procRoot, name)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				var err error
				if strings.HasSuffix(name, "/exe") || strings.Contains(name, "/fd/") {
					err = os.Symlink(value, path)
				} else {
					err = os.WriteFile(path, []byte(value), 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("XDG_CURRENT_DESKTOP", "GNOME")
			t.Setenv("XDG_SESSION_ID", "4")
			session := properties([]byte("ID=4\nUser=1000\nActive=yes\nRemote=no\nType=x11\nClass=user\nDesktop=\nDisplay=\nSeat=seat0\n"))
			for key, value := range tc.sessionChanges {
				session[key] = value
			}
			delete(session, tc.removeSession)
			facts, err := checkXorg(procRoot, session, desktop)
			if err == nil {
				err = validateDesktopSession(session, 1000, desktop, facts)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("readiness error = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

func TestXorgFallbackPreservesLogindRefusals(t *testing.T) {
	desktop := linuxtarget.Desktop{Display: ":0", XAuthority: "/run/user/1000/gdm/Xauthority"}
	facts := xorgDesktopFacts{desktop: "GNOME", display: ":0"}
	session := properties([]byte("ID=4\nUser=1000\nActive=yes\nRemote=no\nType=x11\nClass=user\nDesktop=\nDisplay=\nSeat=seat0\n"))
	if err := validateDesktopSession(session, 1000, desktop, facts); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"User": "2000", "Active": "no", "Remote": "yes", "Type": "wayland", "Class": "greeter", "Desktop": "XFCE", "Display": ":1", "Seat": ""} {
		t.Run(key, func(t *testing.T) {
			original := session[key]
			session[key] = value
			defer func() { session[key] = original }()
			if err := validateDesktopSession(session, 1000, desktop, facts); err == nil {
				t.Fatalf("Xorg fallback accepted %s=%s", key, value)
			}
		})
	}
	for _, incomplete := range []xorgDesktopFacts{{}, {desktop: "GNOME"}, {display: ":0"}} {
		if err := validateDesktopSession(session, 1000, desktop, incomplete); err == nil {
			t.Fatalf("accepted incomplete Xorg fallback %+v", incomplete)
		}
	}
}

const xorgStatFixture = "42 (Xorg) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123456 0 0\n"

func TestXorgProcessIdentityChange(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux /proc symlink contract")
	}
	for _, field := range []string{"stat", "cgroup", "exe"} {
		t.Run(field, func(t *testing.T) {
			base := t.TempDir()
			if err := os.WriteFile(base+"/stat", []byte(xorgStatFixture), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(base+"/cgroup", []byte("0::/user.slice/user-1000.slice/session-4.scope\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/usr/lib/xorg/Xorg", base+"/exe"); err != nil {
				t.Fatal(err)
			}
			identity, err := readXorgProcessIdentity(base)
			if err != nil {
				t.Fatal(err)
			}
			if err := identity.check(base); err != nil {
				t.Fatal(err)
			}
			if field == "exe" {
				if err := os.Remove(base + "/exe"); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink("/usr/bin/Xvfb", base+"/exe")
			} else if field == "stat" {
				err = os.WriteFile(base+"/stat", []byte(strings.ReplaceAll(xorgStatFixture, "123456", "654321")), 0600)
			} else {
				err = os.WriteFile(base+"/cgroup", []byte("0::/user.slice/user-1000.slice/session-40.scope\n"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := identity.check(base); err == nil {
				t.Fatal("accepted changed Xorg process identity")
			}
		})
	}
}
