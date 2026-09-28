package pairing

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/BramVR/blender-box/internal/sshkey"
)

// LineMarkerPrefix ends every pairing-owned authorized_keys line with the pair id it belongs to.
const LineMarkerPrefix = "blender-box-pair:"

// physicalLine spans one line of an authorized_keys file. text excludes the terminator and next
// is the offset after it, so [start,next) is the exact byte range the line owns.
type physicalLine struct{ start, end, next int }

func physicalLines(contents []byte) []physicalLine {
	var lines []physicalLine
	for start := 0; start < len(contents); {
		end := bytes.IndexByte(contents[start:], '\n')
		if end < 0 {
			lines = append(lines, physicalLine{start, len(contents), len(contents)})
			break
		}
		lines = append(lines, physicalLine{start, start + end, start + end + 1})
		start += end + 1
	}
	return lines
}

func lineText(contents []byte, line physicalLine) string {
	return strings.TrimSuffix(string(contents[line.start:line.end]), "\r")
}

func grantLine(publicKey, pairID string) (string, error) {
	if _, err := sshkey.CanonicalPublicKey(publicKey); err != nil {
		return "", err
	}
	if !idPattern.MatchString(pairID) {
		return "", fmt.Errorf("invalid pair id")
	}
	return "restrict " + publicKey + " " + LineMarkerPrefix + pairID, nil
}

// scanKeys counts lines equal to line after stripping one trailing "\r". foreignKey reports the
// same key on any other uncommented line; foreignMarker reports this pair's marker with another key.
func scanKeys(contents []byte, line, publicKey, pairID string) (exact int, foreignKey bool, foreignMarker bool) {
	for _, physical := range physicalLines(contents) {
		text := lineText(contents, physical)
		if text == line {
			exact++
			continue
		}
		fields := strings.Fields(text)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		joined := " " + strings.Join(fields, " ") + " "
		if strings.Contains(joined, " "+publicKey+" ") {
			foreignKey = true
		}
		if strings.Contains(joined, " "+LineMarkerPrefix+pairID+" ") {
			foreignMarker = true
		}
	}
	return exact, foreignKey, foreignMarker
}

// appendLine returns contents + [EOL if contents is non-empty and unterminated] + line + EOL.
// EOL is "\r\n" when contents already use it, otherwise "\n". The prefix bytes are unchanged.
func appendLine(contents []byte, line string) []byte {
	eol := "\n"
	if bytes.Contains(contents, []byte("\r\n")) {
		eol = "\r\n"
	}
	result := append([]byte{}, contents...)
	if len(result) > 0 && result[len(result)-1] != '\n' {
		result = append(result, eol...)
	}
	return append(append(result, line...), eol...)
}

// removeLine deletes exactly one occurrence of line and its own terminator; every other byte stays.
// removeLine(appendLine(x, l), l) == x when x is empty or EOL-terminated, and x+EOL otherwise.
func removeLine(contents []byte, line string) ([]byte, error) {
	var matches []physicalLine
	for _, physical := range physicalLines(contents) {
		if lineText(contents, physical) == line {
			matches = append(matches, physical)
		}
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("expected exactly one pairing line, found %d", len(matches))
	}
	result := append([]byte{}, contents[:matches[0].start]...)
	return append(result, contents[matches[0].next:]...), nil
}
