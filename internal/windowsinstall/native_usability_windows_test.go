//go:build windows

package windowsinstall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const nativeUsabilityMarker = "BLENDER_BOX_NATIVE_USABILITY_ROOT"
const nativeUsabilityValue = "Données 日本語 = native probe"

type nativeUsabilityProbe struct {
	Index      int               `json:"index"`
	Executable string            `json:"executable"`
	Value      string            `json:"value"`
	Version    string            `json:"version"`
	Isolated   bool              `json:"isolated"`
	Process    nativeTestProcess `json:"process"`
	ElapsedNS  int64             `json:"elapsed_ns"`
}

func nativeUsabilityArgs(mode, directory, python string) []string {
	return []string{"-test.run=^TestNativeUsabilityHelper$", "--", mode, directory, python}
}

func TestNativeAdmittedCancellationBeforeResumePreservesTreeExit(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject=%t", reject), func(t *testing.T) {
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			directory := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			admissions, exits, notStarted := 0, 0, 0
			var worker nativeSpawn
			refused := errors.New("ownership publication refused")
			output, err := runNativeJobGated(ctx, executable, ownerNativeArgs("mutate", directory), nil, ownerNativeEnvironment(t), &nativeRunGate{
				Admit: func(spawn nativeSpawn) error {
					admissions++
					worker = spawn
					identity := processIdentity(spawn.Info.ProcessId, spawn.Created)
					if !identity.valid() {
						return fmt.Errorf("worker has no exact creation identity")
					}
					if reject {
						cancel()
						return refused
					}
					if err := publishExecutionJSON(filepath.Join(directory, "ownership.json"), directory, identity, nil); err != nil {
						return err
					}
					cancel()
					return nil
				},
				NotStarted: func() { notStarted++ },
				TreeExited: func(spawn nativeSpawn) {
					exits++
					if spawn.Info.ProcessId != worker.Info.ProcessId || spawn.Created != worker.Created {
						t.Error("cleanup receipt changed admitted worker identity")
					}
					if wait, err := syscall.WaitForSingleObject(spawn.Info.Process, 0); err != nil || wait != syscall.WAIT_OBJECT_0 {
						t.Errorf("cleanup receipt preceded root termination: wait=%d error=%v", wait, err)
					}
				},
			})
			wantError, wantExits := error(context.Canceled), 1
			if reject {
				wantError, wantExits = refused, 0
			}
			if !errors.Is(err, wantError) || errors.Is(err, errNativeCleanupUnknown) || admissions != 1 || exits != wantExits || notStarted != 0 || len(output) != 0 {
				t.Fatalf("pre-resume cancellation lost admission or cleanup outcome: admissions=%d exits=%d not_started=%d output=%q error=%v", admissions, exits, notStarted, output, err)
			}
			for _, name := range []string{"worker.json", "mutated"} {
				if _, err := os.Stat(filepath.Join(directory, name)); !os.IsNotExist(err) {
					t.Fatalf("canceled worker executed before resume: %s error=%v", name, err)
				}
			}
			if !reject {
				var published ProcessIdentity
				if err := readExecutionJSON(filepath.Join(directory, "ownership.json"), &published); err != nil || published != processIdentity(worker.Info.ProcessId, worker.Created) {
					t.Fatalf("admitted worker has no matching durable ownership: identity=%+v error=%v", published, err)
				}
			}
		})
	}
}

func TestNativeNestedInstallerUsability(t *testing.T) {
	for _, mode := range []string{"fast", "powershell", "python"} {
		t.Run(mode, func(t *testing.T) {
			python := ""
			if mode == "python" {
				found, err := exec.LookPath("python")
				if err != nil {
					t.Skipf("read-only Python probe unavailable: python is not on PATH: %v", err)
				}
				python, err = filepath.Abs(found)
				if err != nil {
					t.Fatal(err)
				}
				python, err = filepath.EvalSymlinks(python)
				if err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(python)
				if err != nil || !info.Mode().IsRegular() || !filepath.IsAbs(python) {
					t.Fatalf("Python probe requires an absolute existing regular executable: %q %v", python, err)
				}
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			directory := t.TempDir()
			environment := append(nativeTestEnvironment(t), nativeUsabilityMarker+"="+directory)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			admissions, exits, notStarted := 0, 0, 0
			var worker nativeSpawn
			started := time.Now()
			output, err := runNativeJobGated(ctx, executable, nativeUsabilityArgs(mode, directory, python), nil, environment, &nativeRunGate{
				Admit: func(spawn nativeSpawn) error {
					admissions++
					worker = spawn
					if !processIdentity(spawn.Info.ProcessId, spawn.Created).valid() {
						return fmt.Errorf("worker has no exact creation identity")
					}
					return nil
				},
				NotStarted: func() { notStarted++ },
				TreeExited: func(spawn nativeSpawn) {
					exits++
					if spawn.Info.ProcessId != worker.Info.ProcessId || spawn.Created != worker.Created {
						t.Error("cleanup receipt changed worker identity")
					}
				},
			})
			if err != nil || admissions != 1 || exits != 1 || notStarted != 0 {
				t.Fatalf("normal nested operation must succeed with one exact tree-exit receipt: admissions=%d exits=%d not_started=%d output=%q err=%v", admissions, exits, notStarted, output, err)
			}
			var probes []nativeUsabilityProbe
			if err := json.Unmarshal(output, &probes); err != nil {
				t.Fatalf("worker result %q: %v", output, err)
			}
			count, expectedExecutable := 1, python
			if mode == "fast" {
				count, expectedExecutable = 8, executable
			} else if mode == "powershell" {
				system, err := systemDirectory()
				if err != nil {
					t.Fatal(err)
				}
				expectedExecutable = filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe")
			}
			if len(probes) != count {
				t.Fatalf("completed probe count=%d want=%d", len(probes), count)
			}
			for index, probe := range probes {
				if probe.Index != index || probe.Value != nativeUsabilityValue || !strings.EqualFold(filepath.Clean(probe.Executable), filepath.Clean(expectedExecutable)) {
					t.Fatalf("probe %d returned wrong output or executable: %+v", index, probe)
				}
				if mode == "fast" && (probe.Process.ParentPID != int(worker.Info.ProcessId) || !processIdentity(uint32(probe.Process.PID), probe.Process.Created).valid() || !strings.EqualFold(probe.Process.Executable, executable)) {
					t.Fatalf("child receipt does not belong to the admitted worker: %+v", probe)
				}
				if mode == "python" && (!probe.Isolated || probe.Version == "") {
					t.Fatalf("Python probe was not isolated or returned no version: %+v", probe)
				}
				t.Logf("native usability mode=%s index=%d elapsed_ns=%d", mode, index, probe.ElapsedNS)
			}
			t.Logf("native usability mode=%s success=true tree_exited=%d elapsed=%s", mode, exits, time.Since(started))
		})
	}
}

func TestNativeUsabilityHelper(t *testing.T) {
	directory := os.Getenv(nativeUsabilityMarker)
	if directory == "" {
		return
	}
	separator := -1
	for index, arg := range os.Args {
		if arg == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || len(os.Args) != separator+4 || os.Args[separator+2] != directory || !filepath.IsAbs(directory) {
		os.Exit(80)
	}
	mode, python := os.Args[separator+1], os.Args[separator+3]
	if mode == "child" {
		var probe nativeUsabilityProbe
		if err := json.NewDecoder(os.Stdin).Decode(&probe); err != nil {
			t.Fatal(err)
		}
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		process, err := syscall.GetCurrentProcess()
		if err != nil {
			t.Fatal(err)
		}
		var created, exited, kernel, user syscall.Filetime
		if err := syscall.GetProcessTimes(process, &created, &exited, &kernel, &user); err != nil {
			t.Fatal(err)
		}
		probe.Executable = executable
		probe.Process = nativeTestProcess{PID: os.Getpid(), ParentPID: os.Getppid(), Executable: executable, Created: created}
		if err := json.NewEncoder(os.Stdout).Encode(probe); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	count := 1
	if mode == "fast" {
		count = 8
	}
	probes := make([]nativeUsabilityProbe, 0, count)
	for index := 0; index < count; index++ {
		input, err := json.Marshal(nativeUsabilityProbe{Index: index, Value: nativeUsabilityValue})
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		var output []byte
		switch mode {
		case "fast":
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			output, err = runNativeJob(ctx, executable, nativeUsabilityArgs("child", directory, ""), input, os.Environ())
			if err != nil {
				t.Fatalf("fast nested child %d failed: %v", index, err)
			}
		case "powershell":
			output, err = powerShell(ctx, `[ordered]@{index=$r.index;value=$r.value;executable=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName}|ConvertTo-Json -Compress`, map[string]any{"index": index, "value": nativeUsabilityValue})
		case "python":
			environment, envErr := cleanEnvironment()
			if envErr != nil {
				t.Fatal(envErr)
			}
			output, err = runNative(ctx, python, []string{"-I", "-B", "-c", `import json,sys; r=json.load(sys.stdin.buffer); print(json.dumps(dict(index=r["index"],value=r["value"],executable=sys.executable,version=sys.version,isolated=bool(sys.flags.isolated))))`}, input, environment)
		default:
			t.Fatal("unknown native usability mode " + strconv.Quote(mode))
		}
		if err != nil {
			t.Fatalf("nested %s probe failed: %v", mode, err)
		}
		var probe nativeUsabilityProbe
		if err := json.Unmarshal(output, &probe); err != nil {
			t.Fatalf("nested %s output %q: %v", mode, output, err)
		}
		probe.ElapsedNS = time.Since(started).Nanoseconds()
		probes = append(probes, probe)
	}
	if err := json.NewEncoder(os.Stdout).Encode(probes); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}
