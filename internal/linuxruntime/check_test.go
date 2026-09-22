package linuxruntime

import "testing"

func TestSupportedBlenderVersion(t *testing.T) {
	for _, test := range []struct {
		name   string
		output string
		want   string
	}{
		{name: "release", output: "Blender 5.2.0\n", want: "5.2.0"},
		{name: "official LTS release", output: "Blender 5.2.0 LTS\nBlender build date: 2026-07-14\n", want: "5.2.0"},
		{name: "other release", output: "Blender 5.1.0 LTS\n"},
		{name: "arbitrary suffix", output: "Blender 5.2.0 unsupported\n"},
		{name: "extra LTS suffix", output: "Blender 5.2.0 LTS unsupported\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := blenderVersion([]byte(test.output)); got != test.want {
				t.Fatalf("blenderVersion(%q) = %q, want %q", test.output, got, test.want)
			}
		})
	}
}
