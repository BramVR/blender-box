package windowsinstall

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/host"
)

type stagingChildInput struct {
	Request    Request
	Inspection Inspection
	Claim      *host.SetupClaim
	Stage      string
	Runtime    bool
}
type stagingChildExit struct {
	PID    int
	Parent int
	Stage  string
	Task   taskObservation
}

func TestStagingPublicationChild(t *testing.T) {
	inputPath := os.Getenv("BLENDER_BOX_STAGING_CHILD")
	if inputPath == "" {
		return
	}
	data, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	var input stagingChildInput
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatal(err)
	}
	o, machine, _ := ownerFixture(t)
	machine.inspection = input.Inspection
	o.installer.claim = input.Claim
	o.installer.checkpoint = func(stage string) error {
		phase, destination, _ := strings.Cut(stage, ":")
		wantedPhase, wantedDestination, _ := strings.Cut(input.Stage, ":")
		if stage != input.Stage && !(phase == wantedPhase && filepath.Base(destination) == wantedDestination) {
			return nil
		}
		if err := json.NewEncoder(os.Stdout).Encode(stagingChildExit{os.Getpid(), os.Getppid(), stage, machine.current}); err != nil {
			os.Exit(74)
		}
		os.Exit(73)
		return nil
	}
	if input.Runtime {
		_, err = o.installer.Execute(context.Background(), input.Request)
	} else {
		if strings.HasSuffix(input.Stage, ":cancel.json") {
			o.run = func(ctx context.Context, record executionRequest, publish func(executionOwnership) error) (workerOutcome, *treeExit, error) {
				own := executionOwnership{1, record.claim(), ProcessIdentity{101, "1001"}, ProcessIdentity{102, "1002"}}
				if err := publish(own); err != nil {
					return workerOutcome{}, nil, err
				}
				stop := statusRequest(input.Request)
				stop.Operation, stop.Apply, stop.ExecutionToken = "stop", true, record.Token
				_, err := o.Stop(ctx, stop)
				return workerOutcome{}, nil, err
			}
		}
		_, err = o.Execute(context.Background(), input.Request)
	}
	t.Fatalf("publication checkpoint not reached: %v", err)
}

func interruptPublication(t *testing.T, input stagingChildInput) stagingChildExit {
	t.Helper()
	directory := tempRoot(t)
	path := filepath.Join(directory, "input.json")
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStagingPublicationChild$")
	cmd.Env = append(os.Environ(), "BLENDER_BOX_STAGING_CHILD="+path, "TMPDIR="+directory, "TEMP="+directory, "TMP="+directory)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	started := time.Now().UTC()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	err = cmd.Wait()
	if err == nil || cmd.ProcessState.ExitCode() != 73 {
		t.Fatalf("child PID %d exit=%v output=%s", pid, err, output.String())
	}
	var event stagingChildExit
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatalf("child event: %v %s", err, output.String())
	}
	if event.PID != pid || event.Parent != os.Getpid() || event.Stage == "" {
		t.Fatalf("wrong child evidence: %+v", event)
	}
	t.Logf("spawn PID=%d parent=%d start=%s command=%q; observed exit=73 checkpoint=%s before fake keeper cleanup", pid, event.Parent, started.Format(time.RFC3339Nano), cmd.Args, event.Stage)
	return event
}

func stagingRemnants(t *testing.T, root string) map[string]File {
	t.Helper()
	result := map[string]File{}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), ".install-pending-") {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			file, err := observeFile(path, File{Path: path, Kind: "file", Size: int64(len(data)), SHA256: digest(data)})
			if err != nil {
				return err
			}
			result[path] = file
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return result
}
func requireRemnants(t *testing.T, root string, remnants map[string]File) {
	t.Helper()
	if got := stagingRemnants(t, root); len(got) != len(remnants) {
		t.Errorf("staging remnants changed: got %d want %d", len(got), len(remnants))
	}
	for path, file := range remnants {
		if filepath.Dir(path) != root {
			t.Errorf("staging in strict inventory: %s", path)
		}
		if _, err := observeFile(path, file); err != nil {
			t.Errorf("orphan changed: %v", err)
		}
	}
}

func TestRuntimePublicationAbruptExit(t *testing.T) {
	for _, phase := range []string{"publication-staged", "publication-published"} {
		for _, action := range []string{"retry", "remove"} {
			t.Run(phase+"/"+action, func(t *testing.T) {
				o, machine, request := ownerFixture(t)
				originalRun := o.run
				var remnants map[string]File
				var published *File
				o.run = func(ctx context.Context, record executionRequest, publish func(executionOwnership) error) (workerOutcome, *treeExit, error) {
					own := executionOwnership{1, record.claim(), ProcessIdentity{101, "1001"}, ProcessIdentity{102, "1002"}}
					if err := publish(own); err != nil {
						return workerOutcome{}, nil, err
					}
					claim := record.claim()
					destination := filepath.Join(request.StateRoot, "installations", string(request.InstallationID), "runtime", "blender-box.exe")
					interruptPublication(t, stagingChildInput{record.Request, machine.inspection, &claim, phase + ":" + destination, true})
					remnants = stagingRemnants(t, request.StateRoot)
					if phase == "publication-staged" && len(remnants) != 1 {
						t.Fatalf("missing real staged orphan: %v", remnants)
					}
					receipt, err := readReceipt(filepath.Join(filepath.Dir(filepath.Dir(destination)), "receipt.json"))
					if err != nil || receipt.Pending == nil || receipt.Pending.Path != "runtime/blender-box.exe" {
						t.Fatalf("missing durable pending create: %+v %v", receipt.Pending, err)
					}
					if phase == "publication-published" {
						for _, planned := range receipt.Intent.Files {
							if planned.Path == receipt.Pending.Path {
								file, err := observeFile(destination, planned)
								if err != nil {
									t.Fatal(err)
								}
								file.Path = destination
								published = &file
							}
						}
						if published == nil {
							t.Fatal("published runtime file missing from intent")
						}
					}
					result := record.Preview
					result.State, result.Completion = "partial", "known"
					return workerOutcome{Result: result, TaskMutation: "settled", Error: "worker exited at publication"}, &treeExit{Kind: "tree-empty", Keeper: own.Keeper, Worker: own.Worker, ObservedAt: time.Now().UTC(), WorkerExitObserved: true}, nil
				}
				failed, err := o.Execute(context.Background(), request)
				if err == nil || failed.Execution == nil || failed.Execution.FenceState != "released" {
					t.Fatalf("failed execution: %+v %v", failed.Execution, err)
				}
				o.run = originalRun
				fresh := newOwner(machine)
				status, err := fresh.Status(context.Background(), statusRequest(request))
				if err == nil || status.Execution == nil || status.Execution.Token != failed.Execution.Token {
					t.Fatalf("fresh partial status: %+v %v", status.Execution, err)
				}
				if action == "remove" {
					removal := request
					removal.Operation, removal.OperationID, removal.ExpectedPlan = "remove", "", ""
					result, err := o.installer.Execute(context.Background(), removal)
					if phase == "publication-published" {
						if err == nil || !strings.Contains(err.Error(), "unrecorded creation retained") {
							t.Fatalf("unrecorded runtime creation adopted for removal: %v", err)
						}
						if _, err := observeFile(published.Path, *published); err != nil {
							t.Fatalf("refused removal changed pending runtime bytes or identity: %v", err)
						}
						retried, retryErr := o.Execute(context.Background(), request)
						if retryErr != nil || retried.State != "installed" || retried.Execution == nil || retried.Execution.Token == failed.Execution.Token {
							t.Fatalf("pending creation retry=%s error=%v", retried.State, retryErr)
						}
						result, err = o.installer.Execute(context.Background(), removal)
					}
					if err != nil || result.State != "removed" {
						t.Errorf("settled removal=%s error=%v", result.State, err)
					}
				} else {
					result, err := o.Execute(context.Background(), request)
					if err != nil || result.State != "installed" || result.Execution == nil || result.Execution.Token == failed.Execution.Token {
						t.Errorf("settled retry=%s execution=%+v error=%v", result.State, result.Execution, err)
					}
				}
				requireRemnants(t, request.StateRoot, remnants)
			})
		}
	}
}

func TestExecutionPublicationAbruptExit(t *testing.T) {
	for _, name := range []string{"request.json", "ownership.json", "terminal.json", "cancel.json"} {
		for _, phase := range []string{"publication-staged", "publication-published"} {
			t.Run(name+"/"+phase, func(t *testing.T) {
				o, machine, request := ownerFixture(t)
				event := interruptPublication(t, stagingChildInput{Request: request, Inspection: machine.inspection, Stage: phase + ":" + name})
				machine.current = event.Task
				remnants := stagingRemnants(t, request.StateRoot)
				if phase == "publication-staged" && len(remnants) != 1 {
					t.Fatalf("missing real staged orphan: %v", remnants)
				}
				requireRemnants(t, request.StateRoot, remnants)
				fresh := newOwner(machine)
				fresh.alive = o.alive
				if name == "request.json" && phase == "publication-staged" {
					if _, err := fresh.Status(context.Background(), statusRequest(request)); err == nil {
						t.Error("missing durable request adopted")
					}
					if _, err := o.Execute(context.Background(), request); err == nil {
						t.Error("missing durable request replayed")
					}
					claim, err := host.ReadSetupClaim(request.StateRoot)
					if err != nil {
						t.Fatal(err)
					}
					stop := statusRequest(request)
					stop.Operation, stop.Apply, stop.ExecutionToken = "stop", true, claim.ExecutionToken
					if _, err := fresh.Stop(context.Background(), stop); err == nil {
						t.Error("missing durable request accepted for stop")
					}
					if host.RejectPendingSetup(request.StateRoot) == nil {
						t.Error("missing request released fence")
					}
					return
				}
				status, err := fresh.Status(context.Background(), statusRequest(request))
				if err != nil || status.Execution == nil {
					t.Fatalf("fresh status rejected publication: %+v %v", status.Execution, err)
				}
				observed, err := fresh.observe(context.Background(), request)
				if err != nil {
					t.Fatalf("strict execution reader rejected interrupted publication: %v", err)
				}
				stop := statusRequest(request)
				stop.Operation, stop.Apply, stop.ExecutionToken = "stop", true, observed.request.Token
				stopped, err := fresh.Stop(context.Background(), stop)
				if err != nil || stopped.Execution == nil {
					t.Fatalf("fresh stop: %+v %v", stopped.Execution, err)
				}
				if observed.terminal == nil {
					replay, err := o.Execute(context.Background(), request)
					if err != nil || replay.Execution == nil || replay.Execution.Token != observed.request.Token {
						t.Fatalf("unsettled replay: %+v %v", replay.Execution, err)
					}
					result := observed.request.Preview
					result.State, result.Completion = "partial", "known"
					proof := &treeExit{Kind: "not-started", Keeper: ProcessIdentity{101, "1001"}, ObservedAt: time.Now().UTC()}
					if observed.ownership != nil {
						proof.Kind, proof.Keeper, proof.Worker, proof.WorkerExitObserved = "tree-empty", observed.ownership.Keeper, observed.ownership.Worker, true
					}
					terminal := executionTerminal{1, observed.request.claim(), proof, workerOutcome{Result: result, TaskMutation: "settled", Error: "writer exited at publication"}}
					if err := publishExecutionJSON(filepath.Join(observed.request.directory(), "terminal.json"), request.StateRoot, terminal, nil); err != nil {
						t.Fatal(err)
					}
					settled, err := fresh.Stop(context.Background(), stop)
					if err == nil || settled.Execution == nil || settled.Execution.FenceState != "released" {
						t.Fatalf("settled stop: %+v %v", settled.Execution, err)
					}
				}
				result, err := o.Execute(context.Background(), request)
				if err != nil || result.State != "installed" {
					t.Errorf("settled replay/retry=%s error=%v", result.State, err)
				}
				requireRemnants(t, request.StateRoot, remnants)
			})
		}
	}
}
