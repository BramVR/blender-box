package linuxtarget

import "testing"

func testConfig() Config {
	return Config{Distribution: Distribution, UID: 1000, Home: "/home/operator", WorkRoot: "/home/operator/box", HostExecutable: "/home/operator/box/bin/blender-box", BlenderExecutable: "/opt/blender/blender", UnitName: "blender-box.service", Desktop: Desktop{Display: ":0", XAuthority: "/run/user/1000/gdm/Xauthority"}, Daemon: DaemonRuntime{VenvRoot: "/home/operator/daemon", PythonExecutable: "/home/operator/daemon/bin/python3", ProvenanceID: ProvenanceID}}
}
func TestLinuxTargetHasConcreteSupportedBoundary(t *testing.T) {
	if err := testConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Config){"unsupported distro": func(c *Config) { c.Distribution = "linux" }, "root UID": func(c *Config) { c.UID = 0 }, "relative home": func(c *Config) { c.Home = "home/operator" }, "unscoped host": func(c *Config) { c.HostExecutable = "/usr/bin/blender-box" }, "home root": func(c *Config) { c.WorkRoot = c.Home }, "state interpreter": func(c *Config) {
		c.Daemon.VenvRoot = c.WorkRoot + "/daemon"
		c.Daemon.PythonExecutable = c.Daemon.VenvRoot + "/bin/python3"
	}, "remote display": func(c *Config) { c.Desktop.Display = "remote:0" }, "unsafe unit": func(c *Config) { c.UnitName = "../other.service" }, "unreviewed wheel": func(c *Config) { c.Daemon.ProvenanceID = "latest" }, "alternate python": func(c *Config) { c.Daemon.PythonExecutable = "/usr/bin/python3" }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			config := testConfig()
			change(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("unsafe target accepted")
			}
		})
	}
}
func TestAbsolutePOSIXPathGrammar(t *testing.T) {
	for _, path := range []string{"/home/operator/box/bin/blender-box", "/run/user/1000/gdm/Xauthority", "/opt/blender-5.2/blender"} {
		if err := ValidateAbsolutePath(path); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"/", "relative", "/a/../b", "/a/./b", "/a//b", "/a/", "/a b", "/a\nb", "/a'", "/a%20b", "/a$HOME", "/a;exit", "/a\\b", "/ümlaut"} {
		if err := ValidateAbsolutePath(path); err == nil {
			t.Fatalf("accepted %q", path)
		}
	}
}
