package windowsinstall

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf16"
)

var errNativeCleanupUnknown = errors.New("native process cleanup is unknown")

func nativeEnvironmentBlock(environment []string) ([]uint16, error) {
	environment = slices.Clone(environment)
	slices.SortStableFunc(environment, func(a, b string) int {
		left, _, _ := strings.Cut(a, "=")
		right, _, _ := strings.Cut(b, "=")
		return slices.Compare(utf16.Encode([]rune(strings.ToUpper(left))), utf16.Encode([]rune(strings.ToUpper(right))))
	})
	var block []uint16
	for _, entry := range environment {
		if strings.ContainsRune(entry, 0) {
			return nil, fmt.Errorf("native environment contains NUL")
		}
		block = append(block, utf16.Encode([]rune(entry))...)
		block = append(block, 0)
	}
	block = append(block, 0)
	if len(block) == 1 {
		block = append(block, 0)
	}
	return block, nil
}
