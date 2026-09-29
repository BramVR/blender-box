package windowsinstall

import "testing"

const stockSSHDT = "port 22\naddressfamily any\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:22\nhostkey __PROGRAMDATA__/ssh/ssh_host_rsa_key\nhostkey __PROGRAMDATA__/ssh/ssh_host_ecdsa_key\nhostkey __PROGRAMDATA__/ssh/ssh_host_ed25519_key\npubkeyauthentication yes\nauthorizedkeysfile __PROGRAMDATA__/ssh/administrators_authorized_keys\nsubsystem sftp sftp-server.exe\n"

func TestParseSSHDTReadsTheFirstEntriesAndTheEd25519HostKey(t *testing.T) {
	config, err := parseSSHDT(stockSSHDT)
	want := sshdConfig{Port: 22, PubkeyAuthentication: true, AuthorizedKeysFile: "__PROGRAMDATA__/ssh/administrators_authorized_keys", HostKey: "__PROGRAMDATA__/ssh/ssh_host_ed25519_key"}
	if err != nil || config != want {
		t.Fatalf("got %+v err %v", config, err)
	}
	user, err := parseSSHDT("Port 2222\r\nPubkeyAuthentication no\r\nAuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2\r\nHostKey C:\\keys\\ssh_host_ed25519_key\r\n")
	if err != nil || user != (sshdConfig{Port: 2222, PubkeyAuthentication: false, AuthorizedKeysFile: ".ssh/authorized_keys", HostKey: `C:\keys\ssh_host_ed25519_key`}) {
		t.Fatalf("got %+v err %v", user, err)
	}
	for _, bad := range []string{"", "port 0\nauthorizedkeysfile x\nhostkey a/ssh_host_ed25519_key\n", "port 22\nhostkey a/ssh_host_ed25519_key\n", "port 22\nauthorizedkeysfile x\nhostkey a/ssh_host_rsa_key\n"} {
		if _, err := parseSSHDT(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestExpandAuthorizedKeysAppliesWindowsTokens(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"__PROGRAMDATA__/ssh/administrators_authorized_keys", `C:\ProgramData\ssh\administrators_authorized_keys`},
		{".ssh/authorized_keys", `C:\Users\operator\.ssh\authorized_keys`},
		{"%h/.ssh/authorized_keys", `C:\Users\operator\.ssh\authorized_keys`},
		{"C:/keys/%u/authorized_keys", `C:\keys\operator\authorized_keys`},
		{"C:\\keys\\100%%\\authorized_keys", `C:\keys\100%\authorized_keys`},
	}
	for _, tc := range cases {
		got, err := expandAuthorizedKeys(tc.raw, "operator", `C:\Users\operator`, `C:\ProgramData`)
		if err != nil || got != tc.want {
			t.Fatalf("%q: got %q err %v", tc.raw, got, err)
		}
	}
	for _, bad := range []string{"", "none", "%d/keys", "keys%", "..\\..\\keys", "C:\\keys\\..\\x", "C:\\keys\\a?b"} {
		if _, err := expandAuthorizedKeys(bad, "operator", `C:\Users\operator`, `C:\ProgramData`); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
