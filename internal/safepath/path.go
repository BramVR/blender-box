package safepath

import (
	"fmt"
	"path"
	"strings"
	"unicode/utf16"
)

// ValidateWindowsRelative enforces one portable relative-path grammar for host transfer.
func ValidateWindowsRelative(label, value string) error {
	if value == "" || strings.Contains(value, `\`) || strings.HasPrefix(value, "/") || strings.ContainsAny(value, `<>:"|?*`) {
		return fmt.Errorf("%s %q is unsafe", label, value)
	}
	clean := path.Clean(value)
	if clean != value || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("%s %q is unsafe", label, value)
	}
	for _, component := range strings.Split(value, "/") {
		if strings.TrimRight(component, ". ") != component || windowsReservedName(component) || len(utf16.Encode([]rune(component))) > 255 {
			return fmt.Errorf("%s %q is unsafe", label, value)
		}
		for _, character := range component {
			if character < 32 {
				return fmt.Errorf("%s %q is unsafe", label, value)
			}
		}
	}
	return nil
}

func windowsReservedName(component string) bool {
	base := strings.ToUpper(strings.SplitN(component, ".", 2)[0])
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$":
		return true
	}
	runes := []rune(base)
	if len(runes) != 4 || (string(runes[:3]) != "COM" && string(runes[:3]) != "LPT") {
		return false
	}
	switch runes[3] {
	case '1', '2', '3', '4', '5', '6', '7', '8', '9', '¹', '²', '³':
		return true
	default:
		return false
	}
}
