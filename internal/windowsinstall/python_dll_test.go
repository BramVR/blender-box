package windowsinstall

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func pythonPEFixture(t *testing.T) []byte {
	t.Helper()
	data := make([]byte, 1536)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:], 128)
	copy(data[128:], "PE\x00\x00")
	header := pe.FileHeader{Machine: pe.IMAGE_FILE_MACHINE_AMD64, NumberOfSections: 1, SizeOfOptionalHeader: 240, Characteristics: pe.IMAGE_FILE_EXECUTABLE_IMAGE}
	optional := pe.OptionalHeader64{Magic: 0x20b, NumberOfRvaAndSizes: 16}
	optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT] = pe.DataDirectory{VirtualAddress: 0x1000, Size: 40}
	section := pe.SectionHeader32{VirtualSize: 512, VirtualAddress: 0x1000, SizeOfRawData: 512, PointerToRawData: 1024}
	copy(section.Name[:], ".idata")
	var headers bytes.Buffer
	for _, value := range []any{header, optional, section} {
		if err := binary.Write(&headers, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	copy(data[132:], headers.Bytes())
	binary.LittleEndian.PutUint32(data[1024:], 0x1080)
	binary.LittleEndian.PutUint32(data[1036:], 0x1060)
	binary.LittleEndian.PutUint32(data[1040:], 0x1080)
	copy(data[1120:], "python311.dll\x00")
	binary.LittleEndian.PutUint64(data[1152:], 0x10a0)
	copy(data[1186:], "Py_Main\x00")
	return data
}

func TestPythonRuntimeDLLReadsPinnedPEImports(t *testing.T) {
	path := filepath.Join(tempRoot(t), "python.exe")
	if err := os.WriteFile(path, pythonPEFixture(t), 0600); err != nil {
		t.Fatal(err)
	}
	hash, identity, err := hashPrerequisite(path, true)
	if err != nil {
		t.Fatal(err)
	}
	candidate := Candidate{Path: path, SHA256: hash, Identity: identity}
	want := filepath.Join(filepath.Dir(path), "python311.dll")
	if got, err := pythonRuntimeDLL(candidate); err != nil || got != want {
		t.Fatalf("dll=%q error=%v", got, err)
	}
	candidate.SHA256 = SHA256("changed")
	if _, err := pythonRuntimeDLL(candidate); err == nil {
		t.Fatal("changed executable snapshot accepted")
	}
}

func TestSelectPythonDLL(t *testing.T) {
	for _, dll := range []string{"python311.dll", "python312.dll", "PYTHON313.DLL", "python314.dll"} {
		got, err := selectPythonDLL([]string{"GetLastError:KERNEL32.dll", "Py_Main:" + dll, "Py_Initialize:" + dll})
		if err != nil || got != dll {
			t.Fatalf("dll=%q got=%q error=%v", dll, got, err)
		}
	}
	for _, symbols := range [][]string{
		nil,
		{"Py_Initialize:python311.dll"},
		{"Py_Main:python315.dll"},
		{"Py_Main:python313t.dll"},
		{"Py_Main:python311_d.dll"},
		{"Py_Main:python3.dll"},
		{"Py_Main:C:\\outside\\python311.dll"},
		{"Py_Main:../python311.dll"},
		{"Py_Main:python311.dll", "Py_Initialize:python312.dll"},
		{"Py_Main:python311.dll", "Py_Initialize:python311_d.dll"},
		{"invalid"},
	} {
		if _, err := selectPythonDLL(symbols); err == nil {
			t.Fatalf("accepted imports=%v", symbols)
		}
	}
}
