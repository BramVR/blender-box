package windowsinstall

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/safepath"
	"github.com/BramVR/blender-box/internal/target"
)

func publication(request Request, state string) Publication {
	p := Publication{Status: state, Path: request.TargetOut}
	if request.SaveTarget != "" {
		p.Path = ""
		p.Name = request.SaveTarget
	}
	return p
}
func publicationPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	var missing []string
	for {
		resolved, err := filepath.EvalSymlinks(absolute)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}
		parent := filepath.Dir(absolute)
		if !os.IsNotExist(err) || parent == absolute {
			return "", err
		}
		missing = append(missing, filepath.Base(absolute))
		absolute = parent
	}
}
func validatePublication(request Request) error {
	if request.TargetOut == "" && request.SaveTarget == "" {
		return nil
	}
	if request.Operation != "install" || !filepath.IsAbs(request.TargetOut) || filepath.Clean(request.TargetOut) != request.TargetOut {
		return fmt.Errorf("publication requires an absolute install target destination")
	}
	if request.SaveTarget != "" {
		if err := target.ValidateName(request.SaveTarget); err != nil {
			return err
		}
		if filepath.Base(request.TargetOut) != request.SaveTarget+".json" || filepath.Base(filepath.Dir(request.TargetOut)) != "targets" {
			return fmt.Errorf("saved target destination differs from name")
		}
	}
	root, err := publicationPath(request.StateRoot)
	if err != nil {
		return err
	}
	destination, err := publicationPath(request.TargetOut)
	if err != nil {
		return err
	}
	rootKey, pathKey := safepath.WindowsKey(root), safepath.WindowsKey(destination)
	if pathKey == rootKey || strings.HasPrefix(pathKey, strings.TrimSuffix(rootKey, string(filepath.Separator))+string(filepath.Separator)) {
		return fmt.Errorf("target publication must remain outside the setup state root")
	}
	return nil
}

// PublishTarget completes the worker's declared target publication. It never overwrites an existing target.
func PublishTarget(ctx context.Context, request Request, result Result) (Result, error) {
	if request.TargetOut == "" {
		result.TargetPublication = Publication{Status: "not-requested"}
		return result, nil
	}
	result.TargetPublication = publication(request, "not-published")
	if !request.Apply || result.State != "installed" || result.Target == nil {
		return result, nil
	}
	if err := validatePublication(request); err != nil {
		result.TargetPublication = publication(request, "failed")
		result.TargetPublication.Error = err.Error()
		return result, err
	}
	if err := ctx.Err(); err != nil {
		result.TargetPublication = publication(request, "failed")
		result.TargetPublication.Error = err.Error()
		return result, err
	}
	data, err := json.Marshal(*result.Target)
	if err == nil {
		err = privatefile.Publish(filepath.Dir(request.TargetOut), filepath.Base(request.TargetOut), append(data, '\n'), false)
	}
	if err != nil {
		result.TargetPublication = publication(request, "failed")
		result.TargetPublication.Error = err.Error()
		return result, err
	}
	result.TargetPublication = publication(request, "published")
	return result, nil
}

func publicationFile(request Request, result Result) (*File, error) {
	data, err := json.Marshal(result.Target)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	file, err := observeFile(request.TargetOut, File{Path: request.TargetOut, Kind: "file", Size: int64(len(data)), SHA256: digest(data)})
	if err != nil {
		return nil, err
	}
	return &file, nil
}
func (outcome *workerOutcome) inspectPublication(request Request) {
	if outcome.Result.TargetPublication.Status != "published" {
		return
	}
	file, err := publicationFile(request, outcome.Result)
	outcome.PublicationFile = file
	if err != nil {
		outcome.Result.TargetPublication = publication(request, "failed")
		outcome.Result.TargetPublication.Error = err.Error()
		outcome.Error = err.Error()
	}
}
func validateWorkerOutcome(record executionRequest, outcome workerOutcome) error {
	result := outcome.Result
	if result.SchemaVersion != 1 || result.InstallationID != record.Request.InstallationID || result.OperationID != record.Request.OperationID || result.Plan.PlanSHA256 != record.Preview.Plan.PlanSHA256 {
		return fmt.Errorf("worker result identity changed")
	}
	if outcome.TaskMutation != "settled" && outcome.TaskMutation != "unknown" || result.Completion != "known" && result.Completion != "unknown" {
		return fmt.Errorf("invalid worker completion")
	}
	switch result.State {
	case "planned", "prepared", "partial", "installed", "removing", "removed", "conflict", "unknown":
	default:
		return fmt.Errorf("invalid worker state")
	}
	if result.TargetPublication.Status == "published" {
		file := outcome.PublicationFile
		data, err := json.Marshal(result.Target)
		if err != nil {
			return err
		}
		data = append(data, '\n')
		if file == nil || result.Target == nil || file.Path != record.Request.TargetOut || file.Kind != "file" || file.Size != int64(len(data)) || file.SHA256 != digest(data) || file.Identity == "" {
			return fmt.Errorf("invalid target publication receipt")
		}
	} else if outcome.PublicationFile != nil {
		return fmt.Errorf("unexpected target publication receipt")
	}
	return nil
}
