package safepath

import "testing"

func TestValidateWindowsRelativeRejectsSuperscriptDeviceAliases(t *testing.T) {
	for _, value := range []string{"COM¹.py", "COM²", "COM³.log", "LPT¹.py", "LPT²", "LPT³.log"} {
		t.Run(value, func(t *testing.T) {
			if err := ValidateWindowsRelative("path", value); err == nil {
				t.Fatalf("%q accepted", value)
			}
		})
	}
}
