package windowsinstall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/BramVR/blender-box/internal/host"
	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/strictjson"
)

const executionTimeout = 5 * time.Minute
const bootstrapInputTimeout = 30 * time.Second
const maxExecutions = 64
const maxExecutionRecord = 2 << 20

var errTaskMutationUnknown = errors.New("Task Scheduler mutation completion is unknown")
var executionID = regexp.MustCompile(`^bbxe_[a-f0-9]{32}$`)
var filetimeID = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

type ProcessIdentity struct {
	PID             uint32 `json:"pid"`
	CreatedFiletime string `json:"created_filetime"`
}

func (p ProcessIdentity) valid() bool { return p.PID != 0 && filetimeID.MatchString(p.CreatedFiletime) }

type Execution struct {
	FenceState      string           `json:"fence_state"`
	ProcessState    string           `json:"process_state"`
	Token           string           `json:"token"`
	RequestSHA256   SHA256           `json:"request_sha256"`
	Deadline        time.Time        `json:"deadline"`
	State           string           `json:"state"`
	TreeCleanup     string           `json:"tree_cleanup"`
	TaskMutation    string           `json:"task_mutation"`
	CancelRequested bool             `json:"cancel_requested"`
	Keeper          *ProcessIdentity `json:"keeper,omitempty"`
	Worker          *ProcessIdentity `json:"worker,omitempty"`
}

type executionRequest struct {
	SchemaVersion     int       `json:"schema_version"`
	Token             string    `json:"token"`
	Request           Request   `json:"request"`
	OwnerSID          string    `json:"owner_sid"`
	RootIdentity      string    `json:"root_identity"`
	DirectoryIdentity string    `json:"directory_identity"`
	Deadline          time.Time `json:"deadline"`
	Predecessor       SHA256    `json:"predecessor,omitempty"`
	Bootstrap         File      `json:"bootstrap"`
	Inputs            []File    `json:"inputs"`
	Preview           Result    `json:"preview"`
}

func (r executionRequest) directory() string {
	return filepath.Join(r.Request.StateRoot, "setup-operations", string(r.Request.OperationID), r.Token)
}
func (r executionRequest) claim() host.SetupClaim {
	return host.SetupClaim{SchemaVersion: 1, InstallationID: string(r.Request.InstallationID), OperationID: string(r.Request.OperationID), ExecutionToken: r.Token, RequestSHA256: string(objectDigest(r)), RootIdentity: r.RootIdentity, OwnerSID: r.OwnerSID, Deadline: r.Deadline}
}
func (r executionRequest) validate() error {
	if r.SchemaVersion != 1 || !executionID.MatchString(r.Token) || r.DirectoryIdentity == "" || r.Preview.Plan.PlanSHA256 == "" || r.Request.ExpectedPlan != r.Preview.Plan.PlanSHA256 || !r.Request.Apply || r.Request.ExecutionToken != "" || r.Request.Operation != "install" && r.Request.Operation != "remove" || len(r.Inputs) > maxFiles || r.Bootstrap.Identity == "" || !hex64.MatchString(string(r.Bootstrap.SHA256)) || r.Predecessor != "" && !hex64.MatchString(string(r.Predecessor)) {
		return fmt.Errorf("invalid execution request")
	}
	if r.Preview.InstallationID != r.Request.InstallationID || r.Preview.OperationID != r.Request.OperationID || r.Preview.Inspection.OwnerSID != r.OwnerSID {
		return fmt.Errorf("execution preview identity changed")
	}
	return r.claim().Validate()
}

type executionOwnership struct {
	SchemaVersion int             `json:"schema_version"`
	Claim         host.SetupClaim `json:"claim"`
	Keeper        ProcessIdentity `json:"keeper"`
	Worker        ProcessIdentity `json:"worker"`
}
type treeExit struct {
	Kind               string          `json:"kind"`
	Keeper             ProcessIdentity `json:"keeper"`
	ObservedAt         time.Time       `json:"observed_at"`
	Worker             ProcessIdentity `json:"worker"`
	ActiveProcesses    uint32          `json:"active_processes"`
	WorkerExitObserved bool            `json:"worker_exit_observed"`
}
type workerOutcome struct {
	Result          Result `json:"result"`
	Error           string `json:"error,omitempty"`
	TaskMutation    string `json:"task_mutation"`
	PublicationFile *File  `json:"publication_file,omitempty"`
}
type executionTerminal struct {
	SchemaVersion int             `json:"schema_version"`
	Claim         host.SetupClaim `json:"claim"`
	TreeExit      *treeExit       `json:"tree_exit,omitempty"`
	Outcome       workerOutcome   `json:"outcome"`
}
type executionCancel struct {
	SchemaVersion int             `json:"schema_version"`
	Claim         host.SetupClaim `json:"claim"`
}
type observedExecution struct {
	request   executionRequest
	ownership *executionOwnership
	terminal  *executionTerminal
	cancel    bool
	fenced    bool
}

type owner struct {
	sshRead   sshReadBoundary
	installer *installer
	launch    func(context.Context, Request) (Result, error)
	run       func(context.Context, executionRequest, func(executionOwnership) error) (workerOutcome, *treeExit, error)
	alive     func(ProcessIdentity) (bool, error)
	pins      func(context.Context, Request, Inspection) (File, []File, func(), error)
}

func newOwner(machine machine) *owner {
	return &owner{installer: &installer{machine: machine}, launch: launchNativeKeeper, run: runNativeWorker, alive: nativeProcessAlive, pins: pinExecutionInputs}
}
func emptyResult(request Request) Result {
	return Result{SchemaVersion: 1, InstallationID: request.InstallationID, OperationID: request.OperationID, State: "unknown", Completion: "unknown", Plan: Plan{Files: []File{}}, Inspection: Inspection{BlenderCandidates: []Candidate{}}, Files: []File{}, Retained: []string{}, Problems: []Problem{}, TargetPublication: Publication{Status: "not-requested"}}
}
func validOperationRequest(r Request) error {
	if r.Platform != "windows" || !filepath.IsAbs(r.StateRoot) || filepath.Clean(r.StateRoot) != r.StateRoot || !installID.MatchString(string(r.InstallationID)) || !operationID.MatchString(string(r.OperationID)) {
		return fmt.Errorf("setup execution requires Windows, an absolute state root and preview installation and operation identities")
	}
	return nil
}
func sameExecutionIntent(left, right Request) bool {
	left.ExpectedPlan = ""
	right.ExpectedPlan = ""
	return left == right
}
func (o *owner) Execute(ctx context.Context, request Request) (Result, error) {
	if request.Operation == "status" {
		return o.Status(ctx, request)
	}
	if request.Operation == "stop" {
		return o.Stop(ctx, request)
	}
	if !request.Apply || request.Platform != "windows" {
		return o.installer.Execute(ctx, request)
	}
	if err := validOperationRequest(request); err != nil {
		return problem(emptyResult(request), "invalid-request", err)
	}
	if request.Operation != "install" && request.Operation != "remove" || request.ExecutionToken != "" {
		return problem(emptyResult(request), "invalid-request", fmt.Errorf("invalid setup apply operation"))
	}
	if err := validatePublication(request); err != nil {
		return problem(emptyResult(request), "invalid-publication", err)
	}
	return o.launch(ctx, request)
}

func (o *owner) observe(ctx context.Context, request Request) (observedExecution, error) {
	var zero observedExecution
	if err := validOperationRequest(request); err != nil {
		return zero, err
	}
	inspection, err := o.installer.machine.inspect(ctx, Request{Operation: "status", Platform: request.Platform, StateRoot: request.StateRoot})
	if err != nil {
		return zero, err
	}
	if err := checkPath(request.StateRoot, false); err != nil {
		return zero, err
	}
	directory := filepath.Join(request.StateRoot, "setup-operations", string(request.OperationID))
	if err := checkPath(directory, false); err != nil {
		return zero, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return zero, err
	}
	if len(entries) == 0 || len(entries) > maxExecutions {
		return zero, fmt.Errorf("invalid execution journal size")
	}
	records := map[SHA256]observedExecution{}
	successors := map[SHA256]SHA256{}
	var first SHA256
	for _, entry := range entries {
		if !entry.IsDir() || !executionID.MatchString(entry.Name()) {
			return zero, fmt.Errorf("unknown execution journal entry")
		}
		path := filepath.Join(directory, entry.Name())
		if err := o.installer.machine.securePath(ctx, path, inspection.OwnerSID, false); err != nil {
			return zero, err
		}
		var record executionRequest
		if err := readExecutionJSON(filepath.Join(path, "request.json"), &record); err != nil {
			return zero, err
		}
		if err := record.validate(); err != nil {
			return zero, err
		}
		if record.Request.StateRoot != request.StateRoot || record.Request.InstallationID != request.InstallationID || record.Request.OperationID != request.OperationID || record.Token != entry.Name() || record.OwnerSID != inspection.OwnerSID || record.RootIdentity != inspection.RootIdentity {
			return zero, fmt.Errorf("execution authority changed")
		}
		identity, err := fileIdentity(path)
		if err != nil || identity != record.DirectoryIdentity {
			return zero, fmt.Errorf("execution directory identity changed")
		}
		current := observedExecution{request: record}
		names, err := os.ReadDir(path)
		if err != nil || len(names) > 4 {
			return zero, fmt.Errorf("invalid execution record directory")
		}
		for _, name := range names {
			full := filepath.Join(path, name.Name())
			if err := o.installer.machine.securePath(ctx, full, inspection.OwnerSID, false); err != nil {
				return zero, err
			}
			switch name.Name() {
			case "request.json":
			case "ownership.json":
				var own executionOwnership
				if err := readExecutionJSON(full, &own); err != nil {
					return zero, err
				}
				if own.SchemaVersion != 1 || own.Claim != record.claim() || !own.Keeper.valid() || !own.Worker.valid() || own.Keeper == own.Worker {
					return zero, fmt.Errorf("invalid execution ownership")
				}
				current.ownership = &own
			case "terminal.json":
				var terminal executionTerminal
				if err := readExecutionJSON(full, &terminal); err != nil {
					return zero, err
				}
				if terminal.SchemaVersion != 1 || terminal.Claim != record.claim() || terminal.Outcome.TaskMutation != "settled" && terminal.Outcome.TaskMutation != "unknown" {
					return zero, fmt.Errorf("invalid execution terminal")
				}
				if terminal.Outcome.Result.InstallationID != record.Request.InstallationID || terminal.Outcome.Result.OperationID != record.Request.OperationID || terminal.Outcome.Result.SchemaVersion != 1 {
					return zero, fmt.Errorf("terminal result identity changed")
				}
				if err := validateWorkerOutcome(record, terminal.Outcome); err != nil {
					return zero, err
				}
				current.terminal = &terminal
			case "cancel.json":
				var cancel executionCancel
				if err := readExecutionJSON(full, &cancel); err != nil {
					return zero, err
				}
				if cancel.SchemaVersion != 1 || cancel.Claim != record.claim() {
					return zero, fmt.Errorf("invalid execution cancellation")
				}
				current.cancel = true
			default:
				return zero, fmt.Errorf("unknown execution record")
			}
		}
		if current.terminal != nil && current.terminal.TreeExit != nil {
			proof := current.terminal.TreeExit
			if !proof.Keeper.valid() || proof.ActiveProcesses != 0 || proof.ObservedAt.IsZero() {
				return zero, fmt.Errorf("invalid process cleanup proof")
			}
			switch proof.Kind {
			case "not-started":
				if current.ownership != nil || proof.Worker != (ProcessIdentity{}) || proof.WorkerExitObserved || current.terminal.Outcome.Result.State != "partial" || current.terminal.Outcome.TaskMutation != "settled" {
					return zero, fmt.Errorf("invalid no-start proof")
				}
			case "tree-empty":
				if current.ownership == nil || proof.Worker != current.ownership.Worker || proof.Keeper != current.ownership.Keeper || !proof.WorkerExitObserved {
					return zero, fmt.Errorf("invalid process tree exit proof")
				}
			default:
				return zero, fmt.Errorf("unknown process cleanup proof")
			}
		}
		hash := objectDigest(record)
		records[hash] = current
		if record.Predecessor == "" {
			if first != "" {
				return zero, fmt.Errorf("multiple execution roots")
			}
			first = hash
		} else {
			if _, exists := successors[record.Predecessor]; exists {
				return zero, fmt.Errorf("forked execution chain")
			}
			successors[record.Predecessor] = hash
		}
	}
	current, exists := records[first]
	if !exists {
		return zero, fmt.Errorf("missing execution chain root")
	}
	visited := 1
	for current.terminal != nil {
		next, exists := successors[objectDigest(*current.terminal)]
		if !exists {
			break
		}
		if !current.resumable() {
			return zero, fmt.Errorf("execution resumed without settled partial predecessor")
		}
		following := records[next]
		if !sameExecutionIntent(current.request.Request, following.request.Request) {
			return zero, fmt.Errorf("resumed execution intent changed")
		}
		current = following
		visited++
		if visited > len(records) {
			return zero, fmt.Errorf("cyclic execution chain")
		}
	}
	if visited != len(records) {
		return zero, fmt.Errorf("incomplete execution predecessor chain")
	}
	claim, claimErr := host.ReadSetupClaim(request.StateRoot)
	if claimErr == nil {
		current.fenced = true
		if claim != current.request.claim() {
			return zero, fmt.Errorf("current setup fence differs from execution")
		}
	} else if !os.IsNotExist(claimErr) || !current.settled() {
		return zero, fmt.Errorf("setup execution lacks exact settled authority: %w", claimErr)
	}
	return current, nil
}
func (e observedExecution) settled() bool {
	return e.terminal != nil && e.terminal.TreeExit != nil && e.terminal.Outcome.TaskMutation == "settled" && e.terminal.Outcome.Result.Completion == "known"
}
func (e observedExecution) resumable() bool {
	if !e.settled() {
		return false
	}
	result := e.terminal.Outcome.Result
	return result.State == "partial" || result.State == "installed" && result.TargetPublication.Status == "failed"
}

func (o *owner) result(observed observedExecution) (Result, error) {
	record := observed.request
	result := record.Preview
	fenceState := "released"
	if observed.fenced {
		fenceState = "held"
	}
	execution := Execution{FenceState: fenceState, ProcessState: "unknown", Token: record.Token, RequestSHA256: objectDigest(record), Deadline: record.Deadline, State: "unknown", TreeCleanup: "unknown", TaskMutation: "unknown", CancelRequested: observed.cancel}
	if observed.ownership != nil {
		execution.ProcessState = "started"
		execution.Keeper = &observed.ownership.Keeper
		execution.Worker = &observed.ownership.Worker
	}
	result.State = "unknown"
	result.Completion = "unknown"
	if observed.terminal != nil {
		result = observed.terminal.Outcome.Result
		execution.TaskMutation = observed.terminal.Outcome.TaskMutation
		if observed.terminal.TreeExit != nil {
			execution.TreeCleanup = "known"
			if observed.terminal.TreeExit.Kind == "not-started" {
				execution.ProcessState = "not-started"
				execution.Keeper = &observed.terminal.TreeExit.Keeper
			}
		}
		if observed.settled() {
			execution.State = "terminal"
		} else {
			result.Completion = "unknown"
		}
	} else if observed.ownership != nil {
		alive, err := o.alive(observed.ownership.Keeper)
		if err == nil && alive {
			execution.State = "running"
			result.State = "running"
		}
	}
	result.Execution = &execution
	if observed.terminal != nil && observed.terminal.Outcome.Error != "" {
		if len(result.Problems) == 0 {
			result.Problems = append(result.Problems, Problem{Code: "execution-failed", Message: observed.terminal.Outcome.Error})
		}
		return result, errors.New(observed.terminal.Outcome.Error)
	}
	return result, nil
}
func (o *owner) Status(ctx context.Context, request Request) (Result, error) {
	if request.Apply || request.ExecutionToken != "" {
		return problem(emptyResult(request), "invalid-request", fmt.Errorf("status is read-only and addresses a logical operation"))
	}
	observed, err := o.observe(ctx, request)
	if err != nil {
		return problem(emptyResult(request), "execution-unknown", err)
	}
	return o.result(observed)
}
func (o *owner) Stop(ctx context.Context, request Request) (Result, error) {
	if !request.Apply || !executionID.MatchString(request.ExecutionToken) {
		return problem(emptyResult(request), "invalid-request", fmt.Errorf("stop requires --apply and the exact --execution token"))
	}
	observed, err := o.observe(ctx, request)
	if err != nil {
		return problem(emptyResult(request), "execution-unknown", err)
	}
	if observed.request.Token != request.ExecutionToken {
		return problem(emptyResult(request), "stale-execution", fmt.Errorf("execution token is no longer current"))
	}
	if observed.terminal != nil {
		if observed.settled() {
			if err := o.releaseFence(ctx, observed); err != nil {
				result, _ := o.result(observed)
				return problem(result, "fence-release-failed", err)
			}
			observed.fenced = false
		}
		return o.result(observed)
	}
	claim := observed.request.claim()
	err = publishExecutionJSON(filepath.Join(observed.request.directory(), "cancel.json"), observed.request.Request.StateRoot, executionCancel{1, claim}, o.installer.checkpoint)
	if err != nil {
		return problem(emptyResult(request), "cancel-failed", err)
	}
	observed.cancel = true
	return o.result(observed)
}

func readExecutionJSON(path string, value any) error {
	if err := checkPath(path, false); err != nil {
		return err
	}
	data, err := privatefile.ReadSource(path, maxExecutionRecord)
	if err != nil {
		return err
	}
	return strictjson.Decode(data, value)
}
func publishExecutionJSON(path, staging string, value any, checkpoint func(string) error) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > maxExecutionRecord {
		return fmt.Errorf("execution record exceeds limit")
	}
	if err = publishBytes(path, staging, data, false, checkpoint); err == nil {
		return nil
	}
	existing, readErr := privatefile.ReadSource(path, maxExecutionRecord)
	if readErr == nil && string(existing) == string(data) {
		return nil
	}
	return fmt.Errorf("immutable execution record collision: %w", err)
}

func (o *owner) keep(ctx context.Context, request Request) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, executionTimeout)
	defer cancel()
	if err := validOperationRequest(request); err != nil {
		return problem(emptyResult(request), "invalid-request", err)
	}
	if err := validatePublication(request); err != nil {
		return problem(emptyResult(request), "invalid-publication", err)
	}
	var prior *observedExecution
	observed, err := o.observe(ctx, request)
	if err == nil {
		if !sameExecutionIntent(observed.request.Request, request) || request.ExpectedPlan != "" && request.ExpectedPlan != observed.request.Preview.Plan.PlanSHA256 {
			return problem(emptyResult(request), "intent-conflict", fmt.Errorf("logical operation intent changed"))
		}
		prior = &observed
		if !observed.settled() {
			return o.result(observed)
		}
	} else {
		directory := filepath.Join(request.StateRoot, "setup-operations", string(request.OperationID))
		if _, statErr := os.Lstat(directory); !os.IsNotExist(statErr) {
			return problem(emptyResult(request), "execution-unknown", err)
		}
	}
	var own *host.SetupClaim
	if prior != nil {
		if claim, err := host.ReadSetupClaim(request.StateRoot); err == nil {
			own = &claim
		} else if !os.IsNotExist(err) {
			return problem(emptyResult(request), "execution-unknown", err)
		}
	}
	previewInstaller := *o.installer
	previewInstaller.claim = own
	previewRequest := request
	previewRequest.Apply = false
	preview, err := previewInstaller.Execute(ctx, previewRequest)
	if err != nil {
		return preview, err
	}
	if prior != nil && !prior.resumable() {
		if prior.terminal.Outcome.PublicationFile != nil {
			file := prior.terminal.Outcome.PublicationFile
			if _, err := observeFile(file.Path, *file); err != nil {
				return problem(preview, "target-changed", err)
			}
		}
		if err := o.releaseFence(ctx, *prior); err != nil {
			return problem(preview, "fence-release-failed", err)
		}
		prior.fenced = false
		return o.result(*prior)
	}
	bootstrap, inputs, releasePins, err := o.pins(ctx, request, preview.Inspection)
	if err != nil {
		return problem(preview, "input-pin-failed", err)
	}
	defer releasePins()
	if err = o.installer.ensureRoot(ctx, request.StateRoot, preview.Inspection.OwnerSID); err != nil {
		return problem(preview, "root-creation-failed", err)
	}
	rootLease, err := openPinnedDirectory(request.StateRoot)
	if err != nil {
		return problem(preview, "root-pin-failed", err)
	}
	defer rootLease.Close()
	var directoryLeases []*os.File
	defer func() {
		for _, lease := range directoryLeases {
			_ = lease.Close()
		}
	}()
	var record executionRequest
	err = host.WithSetupMaintenance(ctx, request.StateRoot, own, func() error {
		if prior != nil {
			latest, err := o.observe(ctx, request)
			if err != nil {
				return err
			}
			if !latest.settled() || objectDigest(*latest.terminal) != objectDigest(*prior.terminal) {
				return fmt.Errorf("predecessor changed while acquiring admission")
			}
			entries, err := os.ReadDir(filepath.Dir(latest.request.directory()))
			if err != nil {
				return err
			}
			if len(entries) >= maxExecutions {
				return fmt.Errorf("execution count exceeds limit")
			}
			if own != nil {
				if err := host.ClearSetupClaim(request.StateRoot, *own); err != nil {
					return err
				}
			}
		} else if _, err := os.Lstat(filepath.Join(request.StateRoot, "setup-operations", string(request.OperationID))); !os.IsNotExist(err) {
			return fmt.Errorf("operation admitted concurrently")
		}
		if err := o.installer.machine.securePath(ctx, request.StateRoot, preview.Inspection.OwnerSID, false); err != nil {
			return err
		}
		rootIdentity, err := fileIdentity(request.StateRoot)
		if err != nil {
			return err
		}
		token, err := newID("bbxe_")
		if err != nil {
			return err
		}
		directory := filepath.Join(request.StateRoot, "setup-operations", string(request.OperationID), token)
		for _, path := range []string{filepath.Join(request.StateRoot, "setup-operations"), filepath.Dir(directory), directory} {
			if _, err := os.Lstat(path); os.IsNotExist(err) {
				if err = o.installer.machine.createDirectory(ctx, path, preview.Inspection.OwnerSID); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
			if err = o.installer.machine.securePath(ctx, path, preview.Inspection.OwnerSID, false); err != nil {
				return err
			}
			lease, err := openPinnedDirectory(path)
			if err != nil {
				return err
			}
			directoryLeases = append(directoryLeases, lease)
		}
		directoryIdentity, err := fileIdentity(directory)
		if err != nil {
			return err
		}
		deadline, _ := ctx.Deadline()
		preview.Inspection.RootIdentity = rootIdentity
		request.ExpectedPlan = preview.Plan.PlanSHA256
		record = executionRequest{SchemaVersion: 1, Token: token, Request: request, OwnerSID: preview.Inspection.OwnerSID, RootIdentity: rootIdentity, DirectoryIdentity: directoryIdentity, Deadline: deadline.UTC(), Bootstrap: bootstrap, Inputs: inputs, Preview: preview}
		if prior != nil {
			record.Predecessor = objectDigest(*prior.terminal)
		}
		if err := record.validate(); err != nil {
			return err
		}
		if err := host.PublishSetupClaim(request.StateRoot, record.claim()); err != nil {
			return err
		}
		return publishExecutionJSON(filepath.Join(directory, "request.json"), request.StateRoot, record, o.installer.checkpoint)
	})
	if err != nil {
		return problem(preview, "admission-failed", err)
	}
	workerContext, stopWatching := watchExecutionCancellation(ctx, record)
	defer stopWatching()
	outcome, exit, runErr := o.run(workerContext, record, func(ownership executionOwnership) error {
		if ownership.SchemaVersion != 1 || ownership.Claim != record.claim() || !ownership.Keeper.valid() || !ownership.Worker.valid() || ownership.Keeper == ownership.Worker {
			return fmt.Errorf("invalid native ownership")
		}
		return publishExecutionJSON(filepath.Join(record.directory(), "ownership.json"), record.Request.StateRoot, ownership, o.installer.checkpoint)
	})
	if err := validateWorkerOutcome(record, outcome); err != nil {
		runErr = errors.Join(runErr, err)
		outcome = workerOutcome{}
	}
	if outcome.Result.SchemaVersion != 1 || outcome.Result.InstallationID != request.InstallationID || outcome.Result.OperationID != request.OperationID {
		outcome = workerOutcome{Result: preview, TaskMutation: "unknown", Error: "worker result unavailable"}
		outcome.Result.State = "unknown"
		outcome.Result.Completion = "unknown"
	}
	if runErr != nil {
		if outcome.Error == "" {
			outcome.Error = runErr.Error()
		} else {
			outcome.Error = errors.Join(errors.New(outcome.Error), runErr).Error()
		}
	}
	if exit == nil || outcome.TaskMutation != "settled" {
		outcome.Result.Completion = "unknown"
	}
	terminal := executionTerminal{SchemaVersion: 1, Claim: record.claim(), TreeExit: exit, Outcome: outcome}
	if err := publishExecutionJSON(filepath.Join(record.directory(), "terminal.json"), record.Request.StateRoot, terminal, o.installer.checkpoint); err != nil {
		return problem(outcome.Result, "terminal-publication-failed", err)
	}
	settled := observedExecution{request: record, terminal: &terminal, fenced: true}
	var canceled executionCancel
	if err := readExecutionJSON(filepath.Join(record.directory(), "cancel.json"), &canceled); err == nil && canceled.Claim == record.claim() {
		settled.cancel = true
	}
	var ownership executionOwnership
	if err := readExecutionJSON(filepath.Join(record.directory(), "ownership.json"), &ownership); err == nil {
		settled.ownership = &ownership
	}
	if settled.settled() {
		if err := o.releaseFence(context.WithoutCancel(ctx), settled); err != nil {
			result, _ := o.result(settled)
			return problem(result, "fence-release-failed", err)
		}

		settled.fenced = false
	}
	return o.result(settled)
}
func (o *owner) releaseFence(ctx context.Context, observed observedExecution) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if !observed.settled() {
		return fmt.Errorf("execution cleanup is not settled")
	}
	claim, err := host.ReadSetupClaim(observed.request.Request.StateRoot)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if claim != observed.request.claim() {
		return fmt.Errorf("pending setup identity changed")
	}
	return host.WithSetupMaintenance(ctx, observed.request.Request.StateRoot, &claim, func() error {
		latest, err := o.observe(ctx, observed.request.Request)
		if err != nil {
			return err
		}
		if latest.terminal == nil || objectDigest(*latest.terminal) != objectDigest(*observed.terminal) {
			return fmt.Errorf("terminal execution changed")
		}
		return host.ClearSetupClaim(observed.request.Request.StateRoot, claim)
	})
}
