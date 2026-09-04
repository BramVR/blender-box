package capture

import "testing"

func TestCatalogDefinesStableCaptureContracts(t *testing.T) {
	want := []Definition{
		{Kind: Viewport, EvidencePath: "screenshots/viewport.png", SourcePath: "evidence/screenshots/viewport.png", MediaType: "image/png", Capability: "capture-viewport-v1"},
		{Kind: BlenderWindow, EvidencePath: "screenshots/blender-window.png", SourcePath: "evidence/screenshots/blender-window.png", MediaType: "image/png", Capability: "capture-blender-window-v1"},
		{Kind: Desktop, EvidencePath: "screenshots/desktop.png", SourcePath: "evidence/screenshots/desktop.png", MediaType: "image/png", Capability: "capture-desktop-v1", PrivacySensitive: true},
	}

	got := Definitions()
	if len(got) != len(want) {
		t.Fatalf("definitions = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("definition %d = %+v, want %+v", index, got[index], want[index])
		}
	}
	got[0].EvidencePath = "changed"
	if fresh := Definitions(); fresh[0].EvidencePath != want[0].EvidencePath {
		t.Fatal("Definitions returned mutable catalog storage")
	}
}

func TestCatalogRestrictsMethodsByCaptureKind(t *testing.T) {
	tests := []struct {
		kind   Kind
		method string
		want   bool
	}{
		{Viewport, "offscreen", true},
		{Viewport, "window_grab", true},
		{Viewport, "bpy.ops.screen.screenshot", false},
		{BlenderWindow, "bpy.ops.screen.screenshot", true},
		{Desktop, "windows-copy-from-screen", true},
		{Desktop, "offscreen", false},
		{Kind("unknown"), "offscreen", false},
	}
	for _, test := range tests {
		if got := MethodAllowed(test.kind, test.method); got != test.want {
			t.Errorf("MethodAllowed(%q, %q) = %t, want %t", test.kind, test.method, got, test.want)
		}
	}
}
