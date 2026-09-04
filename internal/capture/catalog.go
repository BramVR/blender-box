package capture

type Kind string

const (
	Viewport      Kind = "viewport"
	BlenderWindow Kind = "blender-window"
	Desktop       Kind = "desktop"
)

type Capability string

type Definition struct {
	Kind             Kind
	EvidencePath     string
	SourcePath       string
	MediaType        string
	Capability       Capability
	PrivacySensitive bool
}

var definitions = []Definition{
	{Kind: Viewport, EvidencePath: "screenshots/viewport.png", SourcePath: "evidence/screenshots/viewport.png", MediaType: "image/png", Capability: "capture-viewport-v1"},
	{Kind: BlenderWindow, EvidencePath: "screenshots/blender-window.png", SourcePath: "evidence/screenshots/blender-window.png", MediaType: "image/png", Capability: "capture-blender-window-v1"},
	{Kind: Desktop, EvidencePath: "screenshots/desktop.png", SourcePath: "evidence/screenshots/desktop.png", MediaType: "image/png", Capability: "capture-desktop-v1", PrivacySensitive: true},
}

func Definitions() []Definition {
	return append([]Definition(nil), definitions...)
}

func Describe(kind Kind) (Definition, bool) {
	for _, definition := range definitions {
		if definition.Kind == kind {
			return definition, true
		}
	}
	return Definition{}, false
}

func MethodAllowed(kind Kind, method string) bool {
	switch kind {
	case Viewport:
		return method == "offscreen" || method == "window_grab"
	case BlenderWindow:
		return method == "bpy.ops.screen.screenshot"
	case Desktop:
		return method == "windows-copy-from-screen"
	default:
		return false
	}
}
