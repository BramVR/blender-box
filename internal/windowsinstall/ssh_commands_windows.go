//go:build windows

package windowsinstall

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"
	"unicode/utf16"
)

func (s *sshNativeReader) commandPath(path string) (string, error) {
	file, err := s.open(path)
	if err != nil {
		return "", err
	}
	return file.(*sshWindowsFile).physical, nil
}
func (s *sshNativeReader) executablePath(path, sid string) (string, error) {
	if err := s.trusted(filepath.Dir(path), sid); err != nil {
		return "", err
	}
	if err := s.trusted(path, sid); err != nil {
		return "", err
	}
	return s.commandPath(path)
}
func (s *sshNativeReader) commandEnvironment() ([]string, error) {
	system, err := systemDirectory()
	if err != nil {
		return nil, err
	}
	if err := s.trusted(system, ""); err != nil {
		return nil, err
	}
	physicalSystem, err := s.commandPath(system)
	if err != nil {
		return nil, err
	}
	if err := s.trusted(filepath.Dir(system), ""); err != nil {
		return nil, err
	}
	physicalWindows, err := s.commandPath(filepath.Dir(system))
	if err != nil {
		return nil, err
	}
	return []string{"SystemRoot=" + physicalWindows, "WINDIR=" + physicalWindows, "PATH=" + physicalSystem}, nil
}
func (s *sshNativeReader) powerShell(ctx context.Context, action string, input any) ([]byte, error) {
	system, err := systemDirectory()
	if err != nil {
		return nil, err
	}
	home := filepath.Join(system, "WindowsPowerShell", "v1.0")
	executable, err := s.executablePath(filepath.Join(home, "powershell.exe"), "")
	if err != nil {
		return nil, err
	}
	if err := s.trusted(filepath.Join(home, "Modules"), ""); err != nil {
		return nil, err
	}
	modules, err := s.commandPath(filepath.Join(home, "Modules"))
	if err != nil {
		return nil, err
	}
	environment, err := s.commandEnvironment()
	if err != nil {
		return nil, err
	}
	environment = append(environment, "PSModulePath="+modules, "PSModuleAnalysisCachePath=nul")
	data, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	script := "$ErrorActionPreference='Stop'\n[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)\n[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n$OutputEncoding=[Console]::OutputEncoding\n$r=ConvertFrom-Json ([Console]::In.ReadToEnd())\n" + nativeFunctions + "\n" + action
	units := utf16.Encode([]rune(script))
	encoded := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[i*2:], unit)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return runNativeJobWithIntent(ctx, nativeTrustedPowerShell, executable, []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded)}, data, environment, nil)
}

type sshReadMachine struct {
	nativeMachine
	reader *sshNativeReader
}

func (m sshReadMachine) task(ctx context.Context, operation string, spec taskSpec) (taskObservation, error) {
	if operation != "inspect" {
		return taskObservation{}, fmt.Errorf("SSH task boundary is read-only")
	}
	data, err := m.reader.powerShell(ctx, taskScript, map[string]any{"operation": operation, "spec": spec})
	if err != nil {
		return taskObservation{}, err
	}
	var result taskObservation
	err = decodeSSHObservation(data, &result)
	return result, err
}
