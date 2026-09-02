package safepath

import (
	"strings"
	"testing"
)

func TestValidateWindowsRelativeRejectsSuperscriptDeviceAliases(t *testing.T) {
	for _, value := range []string{"COM¹.py", "COM²", "COM³.log", "LPT¹.py", "LPT²", "LPT³.log"} {
		t.Run(value, func(t *testing.T) {
			if err := ValidateWindowsRelative("path", value); err == nil {
				t.Fatalf("%q accepted", value)
			}
		})
	}
}

func TestValidateWindowsRelativeRejectsOtherDevicesAndOverlongComponents(t *testing.T) {
	for _, value := range []string{
		"CONIN$",
		"CONOUT$.log",
		strings.Repeat("a", 256),
		strings.Repeat("😀", 128),
	} {
		t.Run(value[:min(len(value), 32)], func(t *testing.T) {
			if err := ValidateWindowsRelative("path", value); err == nil {
				t.Fatalf("path accepted with %d bytes", len(value))
			}
		})
	}
	if err := ValidateWindowsRelative("path", strings.Repeat("😀", 120)); err != nil {
		t.Fatalf("240 UTF-16 code-unit component rejected: %v", err)
	}
	if err := ValidateWindowsRelative("path", strings.Repeat("a", 120)+"/"+strings.Repeat("b", 120)); err == nil {
		t.Fatal("overlong complete relative path accepted")
	}
	if err := ValidateWindowsRelative("path", strings.Repeat("a", 119)+"/"+strings.Repeat("b", 120)); err != nil {
		t.Fatalf("240 UTF-16 code-unit relative path rejected: %v", err)
	}
}
