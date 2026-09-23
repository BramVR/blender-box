//go:build !windows

package main

import "fmt"

func systemDirectory() (string, error) {
	return "", fmt.Errorf("daemon broker requires Windows")
}
