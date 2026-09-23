package windowsinstall

import (
	"reflect"
	"testing"
	"unicode/utf16"
)

func TestNativeEnvironmentBlockOrdersNamesAndPreservesValues(t *testing.T) {
	input := []string{"z=last", "PYTHONDONTWRITEBYTECODE=1", "abc=日本語 🎨=value", "BLENDERSESSIOND_STATE_DIR=C:\\Private"}
	original := append([]string(nil), input...)
	block, err := nativeEnvironmentBlock(input)
	want := "abc=日本語 🎨=value\x00BLENDERSESSIOND_STATE_DIR=C:\\Private\x00PYTHONDONTWRITEBYTECODE=1\x00z=last\x00\x00"
	if err != nil || string(utf16.Decode(block)) != want {
		t.Fatalf("environment block=%q error=%v", string(utf16.Decode(block)), err)
	}
	if !reflect.DeepEqual(input, original) {
		t.Fatal("caller environment changed")
	}
	if _, err := nativeEnvironmentBlock([]string{"key=value\x00other=injected"}); err == nil {
		t.Fatal("NUL accepted")
	}
	block, err = nativeEnvironmentBlock(nil)
	if err != nil || !reflect.DeepEqual(block, []uint16{0, 0}) {
		t.Fatalf("empty environment=%v error=%v", block, err)
	}
}
