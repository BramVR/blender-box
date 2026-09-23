package windowsinstall

import (
	"bytes"
	"debug/pe"
	"fmt"
	"path/filepath"
	"strings"
)

func pythonRuntimeDLL(candidate Candidate) (string, error) {
	if !strings.EqualFold(filepath.Base(candidate.Path), "python.exe") {
		return "", fmt.Errorf("Python prerequisite must be named python.exe")
	}
	before, err := fileIdentity(candidate.Path)
	if err != nil || before != candidate.Identity {
		return "", fmt.Errorf("Python changed before import inspection")
	}
	data, err := readSource(candidate.Path)
	if err != nil {
		return "", err
	}
	after, err := fileIdentity(candidate.Path)
	if err != nil || after != before || digest(data) != candidate.SHA256 {
		return "", fmt.Errorf("Python changed during import inspection")
	}
	image, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	defer image.Close()
	symbols, err := image.ImportedSymbols()
	if err != nil {
		return "", err
	}
	library, err := selectPythonDLL(symbols)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(candidate.Path), library), nil
}

func selectPythonDLL(symbols []string) (string, error) {
	library := ""
	main := false
	for _, symbol := range symbols {
		name, dll, found := strings.Cut(symbol, ":")
		if !found {
			return "", fmt.Errorf("invalid imported symbol")
		}
		lower := strings.ToLower(dll)
		if !strings.HasPrefix(lower, "python") && name != "Py_Main" {
			continue
		}
		switch lower {
		case "python311.dll", "python312.dll", "python313.dll", "python314.dll":
		default:
			return "", fmt.Errorf("unsupported imported Python DLL")
		}
		if library != "" && !strings.EqualFold(library, dll) {
			return "", fmt.Errorf("ambiguous imported Python DLL")
		}
		library = dll
		main = main || name == "Py_Main"
	}
	if library == "" || !main {
		return "", fmt.Errorf("Python requires a supported named Py_Main import")
	}
	return library, nil
}
