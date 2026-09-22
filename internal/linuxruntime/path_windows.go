//go:build windows

package linuxruntime

import "fmt"

func SafePath(string, uint32, bool) error { return fmt.Errorf("Linux paths require native Linux") }
