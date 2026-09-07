package windowsinstall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BramVR/blender-box/internal/host"
	"github.com/BramVR/blender-box/internal/safepath"
	"github.com/BramVR/blender-box/internal/target"
)

type taskSpec struct {
	Name           string         `json:"name"`
	OwnerSID       string         `json:"owner_sid"`
	InstallationID InstallationID `json:"installation_id"`
	Executable     string         `json:"executable"`
	Arguments      string         `json:"arguments"`
	Directory      string         `json:"directory"`
}
type taskObservation struct {
	Exists      bool   `json:"exists"`
	Running     bool   `json:"running"`
	Matches     bool   `json:"matches"`
	Fingerprint SHA256 `json:"fingerprint,omitempty"`
}
type machine interface {
	inspect(context.Context, Request) (Inspection, error)
	securePath(context.Context, string, string, bool) error
	createDirectory(context.Context, string, string) error
	task(context.Context, string, taskSpec) (taskObservation, error)
	probe(context.Context, string, string) error
	target(installIntent) (target.Target, error)
}
type installer struct {
	machine    machine
	checkpoint func(string) error
	claim      *host.SetupClaim
}

func NewLocal() Executor { return newOwner(nativeMachine{}) }

type installIntent struct {
	TargetOut      string             `json:"target_out,omitempty"`
	SaveTarget     string             `json:"save_target,omitempty"`
	Root           string             `json:"root"`
	OwnerSID       string             `json:"owner_sid"`
	SSHAlias       string             `json:"ssh_alias"`
	WindowsUser    string             `json:"windows_user"`
	Blender        Candidate          `json:"blender"`
	Python         PythonPrerequisite `json:"python"`
	ManifestSHA256 SHA256             `json:"manifest_sha256"`
	Task           taskSpec           `json:"task"`
	Files          []File             `json:"files"`
}
type mutation struct {
	Action string `json:"action"`
	Path   string `json:"path"`
}
type installationReceipt struct {
	SchemaVersion   int            `json:"schema_version"`
	InstallationID  InstallationID `json:"installation_id"`
	OperationID     OperationID    `json:"operation_id"`
	RootIdentity    string         `json:"root_identity"`
	Intent          installIntent  `json:"intent"`
	IntentSHA256    SHA256         `json:"intent_sha256"`
	State           string         `json:"state"`
	Generation      uint64         `json:"generation"`
	Files           []File         `json:"files"`
	TaskFingerprint SHA256         `json:"task_fingerprint,omitempty"`
	Pending         *mutation      `json:"pending,omitempty"`
	Deleted         []string       `json:"deleted"`
}

func validateInventory(files []File) (map[string]File, error) {
	if len(files) == 0 || len(files) > maxFiles+32 {
		return nil, fmt.Errorf("invalid runtime inventory size")
	}
	allowed := map[string]File{}
	for _, file := range files {
		if err := safepath.ValidateWindowsRelative("receipt file", file.Path); err != nil {
			return nil, err
		}
		if file.Path != "runtime" && !strings.HasPrefix(file.Path, "runtime/") {
			return nil, fmt.Errorf("receipt outside runtime")
		}
		if file.Kind != "directory" && file.Kind != "file" {
			return nil, fmt.Errorf("invalid component kind")
		}
		if file.Kind == "file" && (!hex64.MatchString(string(file.SHA256)) || file.Size < 0 || file.Size > maxArtifact) {
			return nil, fmt.Errorf("invalid component hash")
		}
		if _, exists := allowed[safepath.WindowsKey(file.Path)]; exists {
			return nil, fmt.Errorf("duplicate receipt path")
		}
		allowed[safepath.WindowsKey(file.Path)] = file
	}
	return allowed, nil
}

func (r installationReceipt) validate() error {
	if r.SchemaVersion != 1 || !installID.MatchString(string(r.InstallationID)) || !operationID.MatchString(string(r.OperationID)) || r.RootIdentity == "" || r.Intent.OwnerSID == "" || r.Intent.Task.InstallationID != r.InstallationID || r.Intent.Root == "" || objectDigest(r.Intent) != r.IntentSHA256 || r.Generation == 0 {
		return fmt.Errorf("invalid installation receipt")
	}
	switch r.State {
	case "prepared", "partial", "installed", "removing", "removed":
	default:
		return fmt.Errorf("invalid installation state")
	}
	allowed, err := validateInventory(r.Intent.Files)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, file := range r.Files {
		expected, exists := allowed[safepath.WindowsKey(file.Path)]
		observed := file
		observed.Identity = ""
		if !exists || seen[file.Path] || file.Identity == "" || objectDigest(expected) != objectDigest(observed) {
			return fmt.Errorf("invalid owned component")
		}
		seen[file.Path] = true
	}
	for _, path := range r.Deleted {
		if path != "task" {
			if _, exists := allowed[safepath.WindowsKey(path)]; !exists {
				return fmt.Errorf("invalid deletion record")
			}
		}
	}
	if r.Pending != nil {
		switch r.Pending.Action {
		case "create", "delete":
			if _, exists := allowed[safepath.WindowsKey(r.Pending.Path)]; !exists {
				return fmt.Errorf("invalid pending path")
			}
		case "create-task", "delete-task":
			if r.Pending.Path != "task" {
				return fmt.Errorf("invalid pending task")
			}
		default:
			return fmt.Errorf("unknown pending mutation")
		}
	}

	deleted := map[string]bool{}
	for _, path := range r.Deleted {
		if deleted[path] {
			return fmt.Errorf("duplicate deletion record")
		}
		deleted[path] = true
		if path != "task" && !seen[path] {
			return fmt.Errorf("deletion without owned component")
		}
	}
	if r.State == "prepared" && (len(r.Files) != 0 || len(r.Deleted) != 0 || r.Pending != nil || r.TaskFingerprint != "") {
		return fmt.Errorf("invalid prepared state")
	}
	if r.State == "installed" && (len(r.Files) != len(r.Intent.Files) || r.TaskFingerprint == "" || r.Pending != nil || len(r.Deleted) != 0) {
		return fmt.Errorf("invalid installed state")
	}
	if r.State == "removed" {
		if r.Pending != nil || r.TaskFingerprint != "" && !deleted["task"] {
			return fmt.Errorf("invalid removed state")
		}
		for _, file := range r.Files {
			if !deleted[file.Path] {
				return fmt.Errorf("removed state retains owned files")
			}
		}
	}
	return nil
}
func (e *installer) Execute(ctx context.Context, request Request) (Result, error) {
	result := Result{TargetPublication: Publication{Status: "not-requested"}, SchemaVersion: 1, InstallationID: request.InstallationID, OperationID: request.OperationID, State: "planned", Completion: "known", Files: []File{}, Retained: []string{}, Problems: []Problem{}, Inspection: Inspection{BlenderCandidates: []Candidate{}}, Plan: Plan{Files: []File{}}}
	if request.Platform != "windows" {
		return problem(result, "unsupported-platform", fmt.Errorf("setup implements Windows only"))
	}
	if request.Operation != "inspect" && request.Operation != "install" && request.Operation != "remove" {
		return problem(result, "unknown-operation", fmt.Errorf("unknown setup operation"))
	}
	if request.Apply && request.Operation == "inspect" {
		return problem(result, "invalid-request", fmt.Errorf("inspect does not accept apply"))
	}
	if !filepath.IsAbs(request.StateRoot) || filepath.Clean(request.StateRoot) != request.StateRoot {
		return problem(result, "invalid-request", fmt.Errorf("state root must be absolute and clean"))
	}
	if request.InstallationID != "" && !installID.MatchString(string(request.InstallationID)) || request.OperationID != "" && !operationID.MatchString(string(request.OperationID)) || request.ExpectedPlan != "" && !hex64.MatchString(string(request.ExpectedPlan)) {
		return problem(result, "invalid-request", fmt.Errorf("invalid installation, operation or plan identity"))
	}
	if request.Operation == "remove" && request.InstallationID == "" {
		return problem(result, "invalid-request", fmt.Errorf("remove requires installation ID"))
	}
	if err := validatePublication(request); err != nil {
		return problem(result, "invalid-publication", err)
	}
	if request.TargetOut != "" {
		result.TargetPublication = publication(request, "not-published")
	}
	inspection, err := e.machine.inspect(ctx, request)
	result.Inspection = inspection
	if err != nil {
		return problem(result, "inspection-failed", err)
	}
	if err = checkPath(request.StateRoot, true); err != nil {
		return problem(result, "unsafe-path", err)
	}
	if err = host.InspectSetupMaintenance(request.StateRoot, e.claim); err != nil {
		return problem(result, "host-busy", err)
	}
	if request.Operation == "inspect" && request.InstallationID == "" {
		if err := e.inspectOtherInstallations(ctx, request.StateRoot, "", inspection.OwnerSID); err != nil {
			return problem(result, "installation-conflict", err)
		}
		return result, nil
	}
	var bundle Bundle
	var contents map[string][]byte
	var intent installIntent
	if request.Operation == "install" {
		if request.RuntimePath == "" || request.SSHAlias == "" || request.WindowsUser == "" || request.TaskName == "" || inspection.Python == nil || len(inspection.BlenderCandidates) != 1 {
			return problem(result, "selection-required", fmt.Errorf("install requires runtime, alias, account, task, Python and one explicit Blender selection"))
		}
		bundle, err = ReadBundle(request.RuntimePath)
		if err != nil {
			return problem(result, "invalid-runtime", err)
		}
		contents, err = runtimeContents(bundle, *inspection.Python)
		if err != nil {
			return problem(result, "invalid-python-template", err)
		}
		if request.InstallationID == "" {
			request.InstallationID, err = e.matchInstallation(request, bundle.SHA256, inspection)
			if err != nil {
				return problem(result, "installation-conflict", err)
			}
		}
		if request.InstallationID == "" {
			id, idErr := newID("bbxi_")
			if idErr != nil {
				return problem(result, "identity-failed", idErr)
			}
			request.InstallationID = InstallationID(id)
		}
		runtime := filepath.Join(request.StateRoot, "installations", string(request.InstallationID), "runtime")
		intent = installIntent{TargetOut: request.TargetOut, SaveTarget: request.SaveTarget, Root: request.StateRoot, OwnerSID: inspection.OwnerSID, SSHAlias: request.SSHAlias, WindowsUser: request.WindowsUser, Blender: inspection.BlenderCandidates[0], Python: *inspection.Python, ManifestSHA256: bundle.SHA256, Task: taskSpec{Name: request.TaskName, OwnerSID: inspection.OwnerSID, InstallationID: request.InstallationID, Executable: filepath.Join(runtime, "blender-box.exe"), Arguments: `host run-request --state-root "` + request.StateRoot + `"`, Directory: runtime}, Files: inventory(contents)}
	}
	if request.Operation == "install" {
		if _, err := validateInventory(intent.Files); err != nil {
			return problem(result, "invalid-inventory", err)
		}
		if _, err := e.machine.target(intent); err != nil {
			return problem(result, "target-invalid", err)
		}
	}
	result.InstallationID = request.InstallationID
	directory := filepath.Join(request.StateRoot, "installations", string(request.InstallationID))
	receiptPath := filepath.Join(directory, "receipt.json")
	receipt, readErr := readReceipt(receiptPath)
	exists := readErr == nil
	if readErr != nil && !os.IsNotExist(readErr) {
		return problem(result, "receipt-conflict", readErr)
	}
	if !exists && request.Operation != "install" {
		return problem(result, "receipt-missing", fmt.Errorf("installation has no ownership receipt"))
	}
	if exists {
		if receipt.InstallationID != request.InstallationID || receipt.Intent.Root != request.StateRoot || receipt.Intent.OwnerSID != inspection.OwnerSID || receipt.RootIdentity != inspection.RootIdentity {
			return problem(result, "receipt-conflict", fmt.Errorf("installation owner or root identity changed"))
		}
		if request.Operation == "install" && objectDigest(intent) != receipt.IntentSHA256 {
			return problem(result, "intent-conflict", fmt.Errorf("immutable installation intent changed; use a fresh installation"))
		}
		intent = receipt.Intent
		result.OperationID = receipt.OperationID
		result.State = receipt.State
		result.Files = receipt.Files
	}
	if !exists {
		if _, err := os.Lstat(directory); err == nil {
			return problem(result, "unowned-collision", fmt.Errorf("installation directory exists without receipt"))
		} else if !os.IsNotExist(err) {
			return problem(result, "inspection-failed", err)
		}
	}
	continuingOperation := exists && (request.Operation != "remove" || receipt.State == "removing" || receipt.State == "removed")
	if continuingOperation && request.OperationID != "" && request.OperationID != receipt.OperationID {
		return problem(result, "operation-conflict", fmt.Errorf("operation identity differs from the installation receipt"))
	}
	if exists && !continuingOperation && request.OperationID == receipt.OperationID {
		return problem(result, "operation-conflict", fmt.Errorf("removal requires a distinct operation identity"))
	}
	if request.OperationID == "" {
		if continuingOperation {
			request.OperationID = receipt.OperationID
		} else {
			id, idErr := newID("bbxo_")
			if idErr != nil {
				return problem(result, "identity-failed", idErr)
			}
			request.OperationID = OperationID(id)
		}
	}
	result.OperationID = request.OperationID
	result.Plan = Plan{PlanSHA256: objectDigest(intent), ManifestSHA256: intent.ManifestSHA256, Files: intent.Files}
	if request.Operation == "remove" {
		result.Plan.PlanSHA256 = objectDigest(struct {
			Kind   string `json:"kind"`
			Intent SHA256 `json:"intent"`
		}{"remove", receipt.IntentSHA256})
	}
	if request.ExpectedPlan != "" && request.ExpectedPlan != result.Plan.PlanSHA256 {
		return problem(result, "plan-changed", fmt.Errorf("expected plan digest differs from current intent"))
	}
	task, err := e.machine.task(ctx, "inspect", intent.Task)
	if err != nil {
		return problem(result, "task-inspection-failed", err)
	}
	if task.Running {
		return problem(result, "task-running", fmt.Errorf("selected task has a running instance"))
	}
	if task.Exists && (!exists || contains(receipt.Deleted, "task") || !task.Matches || receipt.TaskFingerprint != "" && receipt.TaskFingerprint != task.Fingerprint || receipt.TaskFingerprint == "" && (receipt.Pending == nil || receipt.Pending.Action != "create-task")) {
		return problem(result, "task-conflict", fmt.Errorf("task is unowned or changed"))
	}
	if exists && !task.Exists && receipt.TaskFingerprint != "" && !contains(receipt.Deleted, "task") && (receipt.Pending == nil || receipt.Pending.Action != "delete-task") {
		return problem(result, "task-conflict", fmt.Errorf("owned task missing without deletion receipt"))
	}
	if exists {
		if err := e.validateOwned(ctx, directory, receipt); err != nil {
			return problem(result, "ownership-conflict", err)
		}
	}
	if err := e.inspectOtherInstallations(ctx, request.StateRoot, request.InstallationID, inspection.OwnerSID); err != nil {
		return problem(result, "installation-conflict", err)
	}
	if !request.Apply {
		return result, nil
	}
	if request.Operation == "remove" {
		executable, err := os.Executable()
		if err != nil {
			return problem(result, "bootstrap-required", err)
		}
		runtimeRoot := filepath.Join(directory, "runtime") + string(filepath.Separator)
		if strings.HasPrefix(safepath.WindowsKey(executable), safepath.WindowsKey(runtimeRoot)) {
			return problem(result, "bootstrap-required", fmt.Errorf("run removal with the verified bootstrap outside this installation runtime"))
		}
	}
	if request.Operation == "install" && exists && (receipt.State == "removing" || receipt.State == "removed") {
		return problem(result, "intent-conflict", fmt.Errorf("installation removal is terminal; use a new installation ID"))
	}
	if err := e.ensureRoot(ctx, request.StateRoot, inspection.OwnerSID); err != nil {
		return problem(result, "root-creation-failed", err)
	}
	err = host.WithSetupMaintenance(ctx, request.StateRoot, e.claim, func() error {
		if err := e.machine.securePath(ctx, request.StateRoot, inspection.OwnerSID, false); err != nil {
			return err
		}
		if err := e.inspectOtherInstallations(ctx, request.StateRoot, request.InstallationID, inspection.OwnerSID); err != nil {
			return err
		}
		for _, lock := range []string{".operation.lock", ".launch.lock"} {
			if err := e.machine.securePath(ctx, filepath.Join(request.StateRoot, lock), inspection.OwnerSID, false); err != nil {
				return err
			}
		}
		if err := e.ensureSkeleton(ctx, request.StateRoot, inspection.OwnerSID); err != nil {
			return err
		}
		currentRoot, err := fileIdentity(request.StateRoot)
		if err != nil {
			return err
		}
		if exists && currentRoot != receipt.RootIdentity {
			return fmt.Errorf("root identity changed")
		}
		task, err = e.machine.task(ctx, "inspect", intent.Task)
		if err != nil {
			return err
		}
		if task.Running {
			return fmt.Errorf("task-running")
		}
		if exists {
			current, err := readReceipt(receiptPath)
			if err != nil {
				return err
			}
			if objectDigest(current) != objectDigest(receipt) {
				return fmt.Errorf("receipt changed while acquiring fence")
			}
			if err := e.validateOwned(ctx, directory, receipt); err != nil {
				return err
			}
		} else {
			if task.Exists {
				return fmt.Errorf("unowned task collision")
			}
			if err := e.machine.createDirectory(ctx, directory, inspection.OwnerSID); err != nil {
				return err
			}
			receipt = installationReceipt{SchemaVersion: 1, InstallationID: request.InstallationID, OperationID: request.OperationID, RootIdentity: currentRoot, Intent: intent, IntentSHA256: objectDigest(intent), State: "prepared", Files: []File{}, Deleted: []string{}}
			if err := saveReceipt(receiptPath, &receipt, false); err != nil {
				return err
			}
			exists = true
			if err := e.hit("prepared"); err != nil {
				return err
			}
		}
		if request.Operation == "install" {
			fresh, err := e.machine.inspect(ctx, request)
			if err != nil {
				return err
			}
			if fresh.OwnerSID != intent.OwnerSID || fresh.Python == nil || objectDigest(*fresh.Python) != objectDigest(intent.Python) || len(fresh.BlenderCandidates) != 1 || objectDigest(fresh.BlenderCandidates[0]) != objectDigest(intent.Blender) {
				return fmt.Errorf("prerequisite selection changed before publication")
			}
		}
		receipt.OperationID = request.OperationID
		if request.Operation == "remove" {
			return e.remove(ctx, directory, receiptPath, &receipt)
		}
		return e.install(ctx, directory, receiptPath, &receipt, contents)
	})
	if exists {
		if observed, readErr := readReceipt(receiptPath); readErr == nil {
			receipt = observed
		} else {
			err = errors.Join(err, fmt.Errorf("read installation receipt: %w", readErr))
			receipt.State = "partial"
			result.Completion = "unknown"
		}
		result.State = receipt.State
		result.Files = receipt.Files
	}
	result.Retained = []string{request.StateRoot, filepath.Join(request.StateRoot, ".operation.lock"), filepath.Join(request.StateRoot, ".launch.lock"), filepath.Join(request.StateRoot, "runs"), filepath.Join(request.StateRoot, "receipts"), receiptPath}
	if err != nil {
		if exists && result.State != "removed" {
			result.State = "partial"
		}
		return problem(result, "reconciliation-failed", err)
	}
	if result.State == "installed" {
		selected, err := e.machine.target(intent)
		if err != nil {
			return problem(result, "target-invalid", err)
		}
		result.Target = &selected
	}
	return result, nil
}
func (e *installer) hit(name string) error {
	if e.checkpoint != nil {
		return e.checkpoint(name)
	}
	return nil
}
func runtimeContents(bundle Bundle, python PythonPrerequisite) (map[string][]byte, error) {
	template, err := readSource(python.Template.Path)
	if err != nil {
		return nil, err
	}
	if digest(template) != python.Template.SHA256 {
		return nil, fmt.Errorf("Python template changed")
	}
	config := []byte("home = " + python.Home + "\ninclude-system-site-packages = false\nversion = " + python.Candidate.Version + "\nexecutable = " + python.Candidate.Path + "\n")
	files := map[string][]byte{"runtime/blender-box.exe": bundle.data[ArtifactHostExecutable], "runtime/blendersessiond.exe": bundle.data[ArtifactDaemonLauncher], "runtime/python/Scripts/python.exe": template, "runtime/python/pyvenv.cfg": config}
	for path, bytes := range bundle.wheel {
		files["runtime/python/Lib/site-packages/"+path] = bytes
	}
	return files, nil
}
func inventory(contents map[string][]byte) []File {
	directories := map[string]bool{}
	files := []File{}
	for _, path := range sortedKeys(contents) {
		data := contents[path]
		files = append(files, File{Path: path, Kind: "file", Size: int64(len(data)), SHA256: digest(data)})
		for parent := filepath.ToSlash(filepath.Dir(path)); parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
			directories[parent] = true
		}
	}
	result := []File{}
	for _, path := range sortedKeys(directories) {
		result = append(result, File{Path: path, Kind: "directory"})
	}
	return append(result, files...)
}
func (e *installer) matchInstallation(request Request, hash SHA256, inspection Inspection) (InstallationID, error) {
	directory := filepath.Join(request.StateRoot, "installations")
	if err := checkPath(directory, false); os.IsNotExist(err) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return "", err
	}
	if len(entries) > 4096 {
		return "", fmt.Errorf("excessive installation receipts")
	}
	var match InstallationID
	for _, entry := range entries {
		if !installID.MatchString(entry.Name()) {
			return "", fmt.Errorf("unknown installation entry")
		}
		r, err := readReceipt(filepath.Join(directory, entry.Name(), "receipt.json"))
		if err != nil {
			return "", err
		}
		if r.State == "removed" {
			continue
		}
		if r.Intent.Root != request.StateRoot || r.Intent.OwnerSID != inspection.OwnerSID {
			return "", fmt.Errorf("installation owner mismatch")
		}
		if r.Intent.Task.Name != request.TaskName {
			if r.State != "installed" {
				return "", fmt.Errorf("unresolved installation receipt")
			}
			continue
		}
		if r.Intent.ManifestSHA256 != hash || r.Intent.Blender.Path != request.BlenderPath || r.Intent.Python.Candidate.Path != request.PythonPath {
			return "", fmt.Errorf("task belongs to another immutable installation intent")
		}
		if match != "" {
			return "", fmt.Errorf("ambiguous installation")
		}
		match = r.InstallationID
	}
	return match, nil
}
func (e *installer) ensureRoot(ctx context.Context, root, sid string) error {
	if _, err := os.Lstat(root); os.IsNotExist(err) {
		if err := e.machine.createDirectory(ctx, root, sid); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}

func (e *installer) ensureSkeleton(ctx context.Context, root, sid string) error {
	for _, name := range []string{"runs", "receipts", "installations"} {
		path := filepath.Join(root, name)
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			if err := e.machine.createDirectory(ctx, path, sid); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if err = e.machine.securePath(ctx, path, sid, false); err != nil {
			return err
		}
	}
	return nil
}
func (e *installer) validateOwned(ctx context.Context, directory string, r installationReceipt) error {
	allowed := map[string]bool{}
	for _, file := range r.Files {
		if !contains(r.Deleted, file.Path) {
			allowed[file.Path] = true
		}
	}
	if r.Pending != nil && r.Pending.Action == "create" {
		allowed[r.Pending.Path] = true
	}
	runtime := filepath.Join(directory, "runtime")
	if _, err := os.Lstat(runtime); err == nil {
		count := 0
		err = filepath.WalkDir(runtime, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			count++
			if count > maxFiles+64 {
				return fmt.Errorf("excessive runtime entries")
			}
			relative, err := filepath.Rel(directory, path)
			if err != nil {
				return err
			}
			if !allowed[filepath.ToSlash(relative)] || entry.Type()&(os.ModeSymlink|os.ModeIrregular) != 0 {
				return fmt.Errorf("unowned runtime descendant: %s", relative)
			}
			return nil
		})
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := e.machine.securePath(ctx, directory, r.Intent.OwnerSID, false); err != nil {
		return err
	}
	for _, file := range r.Files {
		if contains(r.Deleted, file.Path) {
			if _, err := os.Lstat(filepath.Join(directory, filepath.FromSlash(file.Path))); !os.IsNotExist(err) {
				return fmt.Errorf("deleted component replaced: %s", file.Path)
			}
			continue
		}
		_, err := observeFile(filepath.Join(directory, filepath.FromSlash(file.Path)), file)
		if err != nil {
			if os.IsNotExist(err) && r.Pending != nil && r.Pending.Action == "delete" && r.Pending.Path == file.Path {
				continue
			}
			return err
		}
		if err = e.machine.securePath(ctx, filepath.Join(directory, filepath.FromSlash(file.Path)), r.Intent.OwnerSID, false); err != nil {
			return err
		}
	}
	return nil
}
func (e *installer) install(ctx context.Context, directory, path string, r *installationReceipt, contents map[string][]byte) error {
	for _, file := range r.Intent.Files {
		if owned(r.Files, file.Path) {
			continue
		}
		destination := filepath.Join(directory, filepath.FromSlash(file.Path))
		pending := r.Pending != nil && r.Pending.Action == "create" && r.Pending.Path == file.Path
		if !pending {
			if _, err := os.Lstat(destination); err == nil {
				return fmt.Errorf("unowned component collision: %s", file.Path)
			} else if !os.IsNotExist(err) {
				return err
			}
			r.Pending = &mutation{Action: "create", Path: file.Path}
			r.State = "partial"
			if err := saveReceipt(path, r, true); err != nil {
				return err
			}
			if err := e.hit("before-create:" + file.Path); err != nil {
				return err
			}
		}
		if _, err := os.Lstat(destination); os.IsNotExist(err) {
			if file.Kind == "directory" {
				err = e.machine.createDirectory(ctx, destination, r.Intent.OwnerSID)
			} else {
				data, exists := contents[file.Path]
				if !exists || digest(data) != file.SHA256 {
					return fmt.Errorf("missing planned runtime bytes")
				}
				err = publishBytes(destination, r.Intent.Root, data, false, e.checkpoint)
			}
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if err := e.hit("after-create:" + file.Path); err != nil {
			return err
		}
		observed, err := observeFile(destination, file)
		if err != nil {
			return err
		}
		r.Files = append(r.Files, observed)
		r.Pending = nil
		if err = saveReceipt(path, r, true); err != nil {
			return err
		}
	}
	if err := e.machine.probe(ctx, filepath.Join(directory, "runtime", "blendersessiond.exe"), filepath.Join(directory, "probe-state")); err != nil {
		return err
	}
	observed, err := e.machine.task(ctx, "inspect", r.Intent.Task)
	if err != nil {
		return err
	}
	if observed.Running {
		return fmt.Errorf("task-running")
	}
	if r.TaskFingerprint == "" {
		pending := r.Pending != nil && r.Pending.Action == "create-task"
		if !pending {
			if observed.Exists {
				return fmt.Errorf("unowned task collision")
			}
			r.Pending = &mutation{Action: "create-task", Path: "task"}
			if err := saveReceipt(path, r, true); err != nil {
				return err
			}
			if err := e.hit("before-create:task"); err != nil {
				return err
			}
		}
		if !observed.Exists {
			observed, err = e.machine.task(ctx, "create", r.Intent.Task)
			if err != nil {
				return errors.Join(errTaskMutationUnknown, err)
			}
		}
		if err := e.hit("after-create:task"); err != nil {
			return err
		}
		if !observed.Exists || !observed.Matches || observed.Running || !hex64.MatchString(string(observed.Fingerprint)) {
			return fmt.Errorf("created task failed exact definition check")
		}
		r.TaskFingerprint = observed.Fingerprint
		r.Pending = nil
	} else if !observed.Exists || !observed.Matches || observed.Fingerprint != r.TaskFingerprint {
		return fmt.Errorf("owned task changed")
	}
	r.State = "installed"
	return saveReceipt(path, r, true)
}
func (e *installer) remove(ctx context.Context, directory, path string, r *installationReceipt) error {
	task, err := e.machine.task(ctx, "inspect", r.Intent.Task)
	if err != nil {
		return err
	}
	if task.Running {
		return fmt.Errorf("task-running")
	}
	if task.Exists && contains(r.Deleted, "task") {
		return fmt.Errorf("removed task replaced")
	}
	if task.Exists && (!task.Matches || r.TaskFingerprint == "" || r.TaskFingerprint != task.Fingerprint) {
		return fmt.Errorf("task ownership conflict")
	}
	if r.State == "removed" {
		if task.Exists {
			return fmt.Errorf("removed task replaced")
		}
		return nil
	}
	if r.Pending != nil && (r.Pending.Action == "create" || r.Pending.Action == "create-task") {
		if r.Pending.Action == "create" {
			if _, err := os.Lstat(filepath.Join(directory, filepath.FromSlash(r.Pending.Path))); !os.IsNotExist(err) {
				if err != nil {
					return err
				}
				return fmt.Errorf("unrecorded creation retained: %s", r.Pending.Path)
			}
		}
		r.Pending = nil
		r.State = "removing"
		if err := saveReceipt(path, r, true); err != nil {
			return err
		}
	}
	if task.Exists || r.TaskFingerprint != "" && !contains(r.Deleted, "task") {
		if !task.Exists && (r.Pending == nil || r.Pending.Action != "delete-task") {
			return fmt.Errorf("owned task missing without deletion receipt")
		}
		r.State = "removing"
		r.Pending = &mutation{Action: "delete-task", Path: "task"}
		if err := saveReceipt(path, r, true); err != nil {
			return err
		}
		if err := e.hit("before-delete:task"); err != nil {
			return err
		}
		if task.Exists {
			after, err := e.machine.task(ctx, "delete", r.Intent.Task)
			if err != nil {
				return errors.Join(errTaskMutationUnknown, err)
			}
			if after.Exists {
				return fmt.Errorf("task removal not confirmed")
			}
		}
		if err := e.hit("after-delete:task"); err != nil {
			return err
		}
		r.Deleted = append(r.Deleted, "task")
		r.Pending = nil
		if err := saveReceipt(path, r, true); err != nil {
			return err
		}
	}
	files := append([]File(nil), r.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path > files[j].Path })
	for _, file := range files {
		if contains(r.Deleted, file.Path) {
			continue
		}
		destination := filepath.Join(directory, filepath.FromSlash(file.Path))
		_, err := observeFile(destination, file)
		missing := os.IsNotExist(err)
		if err != nil && !(missing && r.Pending != nil && r.Pending.Action == "delete" && r.Pending.Path == file.Path) {
			return err
		}
		if file.Kind == "directory" && !missing {
			entries, err := os.ReadDir(destination)
			if err != nil {
				return err
			}
			if len(entries) != 0 {
				return fmt.Errorf("retained unknown descendants in %s", file.Path)
			}
		}
		r.State = "removing"
		r.Pending = &mutation{Action: "delete", Path: file.Path}
		if err := saveReceipt(path, r, true); err != nil {
			return err
		}
		if err := e.hit("before-delete:" + file.Path); err != nil {
			return err
		}
		if !missing {
			if err := e.machine.securePath(ctx, destination, r.Intent.OwnerSID, false); err != nil {
				return err
			}
			if err := removeOwnedFile(destination, file); err != nil {
				return err
			}
		}
		if err := e.hit("after-delete:" + file.Path); err != nil {
			return err
		}
		r.Deleted = append(r.Deleted, file.Path)
		r.Pending = nil
		if err := saveReceipt(path, r, true); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(filepath.Join(directory, "runtime")); !os.IsNotExist(err) {
		return fmt.Errorf("retained runtime without complete deletion authority")
	}
	r.State = "removed"
	return saveReceipt(path, r, true)
}
func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func owned(values []File, want string) bool {
	for _, value := range values {
		if value.Path == want {
			return true
		}
	}
	return false
}

func (e *installer) inspectOtherInstallations(ctx context.Context, root string, selected InstallationID, sid string) error {
	directory := filepath.Join(root, "installations")
	if err := checkPath(directory, false); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	if len(entries) > 4096 {
		return fmt.Errorf("excessive installations")
	}
	for _, entry := range entries {
		if !installID.MatchString(entry.Name()) || !entry.IsDir() {
			return fmt.Errorf("unknown installation record")
		}
		if InstallationID(entry.Name()) == selected {
			continue
		}
		r, err := readReceipt(filepath.Join(directory, entry.Name(), "receipt.json"))
		if err != nil {
			return err
		}
		if r.Intent.OwnerSID != sid || r.Intent.Root != root {
			return fmt.Errorf("foreign installation authority")
		}
		if r.State == "removed" {
			continue
		}
		if r.State != "installed" {
			return fmt.Errorf("unresolved other installation")
		}
		observed, err := e.machine.task(ctx, "inspect", r.Intent.Task)
		if err != nil {
			return err
		}
		if observed.Running || !observed.Exists || !observed.Matches || observed.Fingerprint != r.TaskFingerprint {
			return fmt.Errorf("other installation task is active or changed")
		}
	}
	return nil
}
