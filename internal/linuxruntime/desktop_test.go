package linuxruntime

import (
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
	for key, value := range map[string]string{"Requires": "basic.target app.slice other.service", "DropInPaths": "/home/operator/override.conf", "EnvironmentFiles": "/home/operator/.profile", "ExitType": "main", "KillMode": "control-group", "Restart": "always", "PartOf": "graphical-session.target", "Slice": "session.slice", "FragmentPath": "/tmp/foreign.service", "NeedDaemonReload": "yes", "ExecStop": "/usr/bin/killall blender"} {
		t.Run(key, func(t *testing.T) {
			facts := properties([]byte(fixture))
			facts[key] = value
			if err := validate(facts); err == nil {
				t.Fatalf("accepted effective %s drift", key)
			}
		})
	}
	facts := properties([]byte(fixture))
	delete(facts, "DropInPaths")
	if err := validate(facts); err == nil {
		t.Fatal("accepted incomplete unit inspection")
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
				err := validateDesktopSession(fields, 1000, desktop)
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
	if err := validateDesktopSession(fields, 1000, desktop); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"User": "2000", "Active": "no", "Remote": "yes", "Type": "wayland", "Class": "greeter", "Desktop": "XFCE", "Display": ":1", "Seat": ""} {
		original := fields[key]
		fields[key] = value
		if err := validateDesktopSession(fields, 1000, desktop); err == nil {
			t.Fatalf("accepted %s=%s", key, value)
		}
		fields[key] = original
	}
	if !strings.Contains(UnitUnavailable("failed").Error(), "operator inspect and reset") {
		t.Fatal("failed unit requires explicit operator recovery")
	}
}
