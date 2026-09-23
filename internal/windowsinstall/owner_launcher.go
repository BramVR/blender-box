package windowsinstall

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BramVR/blender-box/internal/host"
)

// LauncherPolicy is part of the approved plan, before an execution token exists.
type LauncherPolicy struct {
	Kind               string `json:"kind"`
	NameTemplate       string `json:"name_template"`
	Action             string `json:"action"`
	Principal          string `json:"principal"`
	Triggers           string `json:"triggers"`
	Instances          string `json:"instances"`
	DeadlineSeconds    int    `json:"deadline_seconds"`
	ExecutionTimeLimit string `json:"execution_time_limit"`
	Cleanup            string `json:"cleanup"`
}

func setupLauncherPolicy() LauncherPolicy {
	return LauncherPolicy{"per-execution-task", "BlenderBox-Setup-<execution-token>", "<pinned-bootstrap> __setup-keeper <private-execution-directory> <request-sha256>", "same-SID limited interactive", "none", "IgnoreNew", 300, "PT6M", "external exact inactive task deletion after keeper exit and worker settlement"}
}
func launcherName(token string) string { return "BlenderBox-Setup-" + token }
func (r executionRequest) launcherTask() taskSpec {
	return taskSpec{Name: r.Launcher, OwnerSID: r.OwnerSID, InstallationID: r.Request.InstallationID, Executable: r.Bootstrap.Path,
		Arguments: `__setup-keeper "` + r.directory() + `" ` + string(objectDigest(r)), Directory: filepath.Dir(r.Bootstrap.Path), ExecutionTimeLimit: setupLauncherPolicy().ExecutionTimeLimit,
		Marker: "Blender Box setup " + string(r.Request.InstallationID) + " " + string(r.Request.OperationID) + " " + r.Token + " " + string(objectDigest(r))}
}

type launcherFact struct {
	SchemaVersion int              `json:"schema_version"`
	Claim         host.SetupClaim  `json:"claim"`
	State         string           `json:"state"`
	Fingerprint   SHA256           `json:"fingerprint,omitempty"`
	Keeper        *ProcessIdentity `json:"keeper,omitempty"`
}

func (f launcherFact) validate(r executionRequest, filename string) error {
	if f.SchemaVersion != 1 || f.Claim != r.claim() || filename != "launcher-"+f.State+".json" {
		return fmt.Errorf("launcher fact identity changed")
	}
	switch f.State {
	case "submitted":
		if f.Fingerprint != "" {
			return fmt.Errorf("submission has unexpected fingerprint")
		}
	case "registered", "run-submitted", "started", "keeper", "delete-submitted", "cleaned":
		if !hex64.MatchString(string(f.Fingerprint)) {
			return fmt.Errorf("launcher fingerprint missing")
		}
	default:
		return fmt.Errorf("unknown launcher fact")
	}
	if f.State == "keeper" {
		if f.Keeper == nil || !f.Keeper.valid() {
			return fmt.Errorf("launcher keeper identity missing")
		}
	} else if f.Keeper != nil {
		return fmt.Errorf("unexpected launcher keeper identity")
	}
	return nil
}
func (o *owner) publishLauncher(r executionRequest, state string, fingerprint SHA256, keeper *ProcessIdentity) error {
	fact := launcherFact{1, r.claim(), state, fingerprint, keeper}
	return publishExecutionJSON(filepath.Join(r.directory(), "launcher-"+state+".json"), r.Request.StateRoot, fact, o.installer.checkpoint)
}
func (e observedExecution) validateLauncher() error {
	dependencies := map[string]string{"registered": "submitted", "run-submitted": "registered", "started": "run-submitted", "keeper": "started", "delete-submitted": "keeper", "cleaned": "delete-submitted"}
	for state, fact := range e.launcher {
		if prior := dependencies[state]; prior != "" {
			previous, ok := e.launcher[prior]
			if !ok || prior != "submitted" && previous.Fingerprint != fact.Fingerprint {
				return fmt.Errorf("incomplete launcher journal")
			}
		}
	}
	keeper := e.launcher["keeper"].Keeper
	if e.ownership != nil && (keeper == nil || *keeper != e.ownership.Keeper) {
		return fmt.Errorf("worker keeper differs from launcher keeper")
	}
	if e.terminal != nil && e.terminal.TreeExit != nil && (keeper == nil || *keeper != e.terminal.TreeExit.Keeper) {
		return fmt.Errorf("terminal keeper differs from launcher keeper")
	}
	if _, ok := e.launcher["cleaned"]; ok && !e.workerSettled() {
		return fmt.Errorf("launcher cleaned before worker settlement")
	}
	return nil
}
func (o *owner) launchExecution(ctx context.Context, r executionRequest) (Result, error) {
	fail := func(err error) (Result, error) {
		observed, observeErr := o.observe(context.WithoutCancel(ctx), r.Request)
		if observeErr != nil {
			result := r.Preview
			result.State, result.Completion = "unknown", "unknown"
			return problem(result, "launcher-unknown", err)
		}
		result, _ := o.result(observed)
		return problem(result, "launcher-unknown", err)
	}
	if err := o.publishLauncher(r, "submitted", "", nil); err != nil {
		return fail(err)
	}
	task, err := o.installer.machine.task(ctx, "create", r.launcherTask())
	if err != nil {
		return fail(err)
	}
	if !task.Exists || !task.Matches || task.Running || !hex64.MatchString(string(task.Fingerprint)) {
		return fail(fmt.Errorf("launcher registration was not confirmed"))
	}
	if err = o.publishLauncher(r, "registered", task.Fingerprint, nil); err != nil {
		return fail(err)
	}
	if err = o.publishLauncher(r, "run-submitted", task.Fingerprint, nil); err != nil {
		return fail(err)
	}
	started, err := o.installer.machine.task(ctx, "run", r.launcherTask())
	if err != nil {
		return fail(err)
	}
	if !started.Exists || !started.Matches || started.Fingerprint != task.Fingerprint {
		return fail(fmt.Errorf("launcher Run completion was not confirmed"))
	}
	if err = o.publishLauncher(r, "started", task.Fingerprint, nil); err != nil {
		return fail(err)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		observed, err := o.observe(ctx, r.Request)
		if err != nil {
			return fail(err)
		}
		if observed.workerSettled() {
			keeper := observed.launcher["keeper"].Keeper
			if keeper == nil {
				return fail(fmt.Errorf("launcher keeper identity missing"))
			}
			alive, err := o.alive(*keeper)
			if err != nil {
				return fail(err)
			}
			if !alive {
				task, err := o.installer.machine.task(ctx, "inspect", r.launcherTask())
				if err != nil {
					return fail(err)
				}
				if !task.Running {
					if err := o.settleLauncher(ctx, &observed); err != nil {
						return fail(err)
					}
					if err := o.releaseFence(ctx, observed); err != nil {
						return fail(err)
					}
					observed.fenced = false
					return o.result(observed)
				}
			}
		} else if observed.terminal != nil {
			return o.result(observed)
		}
		select {
		case <-ctx.Done():
			return fail(ctx.Err())
		case <-ticker.C:
		}
	}
}
func (o *owner) settleLauncher(ctx context.Context, e *observedExecution) error {
	if !e.workerSettled() {
		return fmt.Errorf("worker cleanup is unsettled")
	}
	if e.launcher["cleaned"].State == "cleaned" {
		return nil
	}
	claim := e.request.claim()
	return host.WithSetupMaintenance(ctx, e.request.Request.StateRoot, &claim, func() error {
		latest, err := o.observe(ctx, e.request.Request)
		if err != nil {
			return err
		}
		if latest.request.Token != e.request.Token || !latest.workerSettled() {
			return fmt.Errorf("execution changed before launcher cleanup")
		}
		*e = latest
		if e.launcher["cleaned"].State == "cleaned" {
			return nil
		}
		if e.launcher["delete-submitted"].State != "" {
			return fmt.Errorf("launcher deletion completion is unknown")
		}
		keeper := e.launcher["keeper"].Keeper
		if keeper == nil {
			return fmt.Errorf("launcher keeper identity missing")
		}
		alive, err := o.alive(*keeper)
		if err != nil {
			return err
		}
		if alive {
			return fmt.Errorf("launcher keeper has not exited")
		}
		task, err := o.installer.machine.task(ctx, "inspect", e.request.launcherTask())
		if err != nil {
			return err
		}
		fingerprint := e.launcher["registered"].Fingerprint
		if !task.Exists || !task.Matches || task.Running || task.Fingerprint != fingerprint {
			return fmt.Errorf("launcher cleanup authority changed")
		}
		if err := o.publishLauncher(e.request, "delete-submitted", fingerprint, nil); err != nil {
			return err
		}
		task, err = o.installer.machine.task(ctx, "delete", e.request.launcherTask())
		if err != nil {
			return err
		}
		if task.Exists {
			return fmt.Errorf("launcher deletion was not confirmed")
		}
		if err := o.publishLauncher(e.request, "cleaned", fingerprint, nil); err != nil {
			return err
		}
		e.launcher["cleaned"] = launcherFact{1, claim, "cleaned", fingerprint, nil}
		return nil
	})
}

func (o *owner) admitKeeper(ctx context.Context, r executionRequest, self ProcessIdentity) (func(), error) {
	ctx, cancel := context.WithDeadline(ctx, r.Deadline)
	defer cancel()
	if err := r.validate(); err != nil {
		return nil, err
	}
	if remaining := time.Until(r.Deadline); remaining <= 0 || remaining > executionTimeout {
		return nil, fmt.Errorf("keeper execution deadline is invalid")
	}
	var pins []*os.File
	release := func() {
		for _, f := range pins {
			_ = f.Close()
		}
	}
	fail := func(err error) (func(), error) { release(); return nil, err }
	for _, path := range []string{r.Request.StateRoot, filepath.Dir(r.directory()), r.directory()} {
		pin, err := openPinnedDirectory(path)
		if err != nil {
			return fail(err)
		}
		pins = append(pins, pin)
	}
	requestPin, err := openPinnedSource(filepath.Join(r.directory(), "request.json"))
	if err != nil {
		return fail(err)
	}
	pins = append(pins, requestPin)
	for _, input := range append([]File{r.Bootstrap}, r.Inputs...) {
		pin, err := openPinnedSource(input.Path)
		if err != nil {
			return fail(err)
		}
		pins = append(pins, pin)
		if err := verifyExecutionInput(input); err != nil {
			return fail(err)
		}
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		observed, err := o.observe(ctx, r.Request)
		if err != nil {
			return fail(err)
		}
		if observed.request.Token != r.Token || observed.terminal != nil || observed.ownership != nil || observed.launcher["keeper"].State != "" || observed.cancel {
			return fail(fmt.Errorf("keeper admission changed"))
		}
		if observed.launcher["started"].State != "" {
			task, err := o.installer.machine.task(ctx, "inspect", r.launcherTask())
			if err != nil {
				return fail(err)
			}
			if !task.Exists || !task.Matches || !task.Running || task.Fingerprint != observed.launcher["registered"].Fingerprint {
				return fail(fmt.Errorf("keeper task authority changed"))
			}
			claim := r.claim()
			if err := host.InspectSetupMaintenance(r.Request.StateRoot, &claim); err != nil {
				return fail(err)
			}
			if err := ctx.Err(); err != nil {
				return fail(err)
			}
			if err := o.publishLauncher(r, "keeper", task.Fingerprint, &self); err != nil {
				return fail(err)
			}
			return release, nil
		}
		select {
		case <-ctx.Done():
			return fail(ctx.Err())
		case <-ticker.C:
		}
	}
}
