package safepath

import (
	"fmt"
	"path"
	"strings"
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
		if strings.TrimRight(component, ". ") != component || windowsReservedName(component) {
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
	case "CON", "PRN", "AUX", "NUL", "CLOCK$":
		return true
	}
	return len(base) == 4 &&
		(strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) &&
		base[3] >= '1' && base[3] <= '9'
}
