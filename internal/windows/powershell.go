package windows

import "strings"

// powerShellLiteral returns one inert single-quoted PowerShell string literal.
func powerShellLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
