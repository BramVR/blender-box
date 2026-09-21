package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/BramVR/blender-box/internal/target"
)

type targetSelection struct{ path, name *string }

func targetFlags(flags *flag.FlagSet) targetSelection {
	return targetSelection{path: flags.String("target", "", "path to target JSON"), name: flags.String("target-name", "", "saved local target name")}
}
func (selection targetSelection) valid(flags *flag.FlagSet) bool {
	var pathPresent, namePresent bool
	flags.Visit(func(value *flag.Flag) {
		if value.Name == "target" {
			pathPresent = true
		}
		if value.Name == "target-name" {
			namePresent = true
		}
	})
	return pathPresent != namePresent && (*selection.path != "" || *selection.name != "")
}
func (selection targetSelection) resolve() (target.Target, error) {
	root, err := target.ConfigDir()
	if err != nil {
		return target.Target{}, err
	}
	if *selection.path != "" {
		return target.Load(*selection.path)
	}
	return (target.Store{Root: root}).Resolve(*selection.name)
}

func targetsCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	operation := args[0]
	if operation != "import" && operation != "list" && operation != "show" && operation != "forget" {
		printUsage(stderr)
		return 2
	}
	args = args[1:]
	name := ""
	if operation != "list" {
		if len(args) == 0 {
			fmt.Fprintln(stderr, "targets command requires NAME")
			return 2
		}
		name, args = args[0], args[1:]
		if err := target.ValidateName(name); err != nil {
			return fail(stderr, "target name", err)
		}
	}
	flags := flag.NewFlagSet("targets "+operation, flag.ContinueOnError)
	flags.SetOutput(stderr)
	asJSON := flags.Bool("json", false, "print versioned JSON")
	var source *string
	var replace *bool
	if operation == "import" {
		source = flags.String("file", "", "source target JSON")
		replace = flags.Bool("replace", false, "replace existing saved target")
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || operation == "import" && *source == "" {
		fmt.Fprintln(stderr, "invalid targets arguments; import requires --file PATH")
		return 2
	}
	root, err := target.ConfigDir()
	if err != nil {
		return fail(stderr, "target storage", err)
	}
	store := target.Store{Root: root}
	if operation == "list" {
		entries, err := store.List()
		if err != nil {
			return fail(stderr, "list targets", err)
		}
		if *asJSON {
			return writeJSON(stdout, stderr, struct {
				SchemaVersion int            `json:"schema_version"`
				Targets       []target.Entry `json:"targets"`
			}{1, entries})
		}
		for _, entry := range entries {
			fmt.Fprintf(stdout, "%s (%s)\n", entry.Name, entry.Platform)
		}
		return 0
	}
	var selected target.Target
	switch operation {
	case "import":
		selected, err = store.Import(name, *source, *replace)
	case "show":
		selected, err = store.Show(name)
	case "forget":
		selected, err = store.Forget(name)
	}
	if err != nil {
		return fail(stderr, operation+" target", err)
	}
	if operation == "show" {
		return writeJSON(stdout, stderr, struct {
			SchemaVersion int           `json:"schema_version"`
			Name          string        `json:"name"`
			Platform      string        `json:"platform"`
			Target        target.Target `json:"target"`
		}{1, name, selected.Platform(), selected})
	}
	status := "imported"
	if operation == "forget" {
		status = "forgotten"
	}
	if *asJSON {
		return writeJSON(stdout, stderr, struct {
			SchemaVersion int    `json:"schema_version"`
			Name          string `json:"name"`
			Platform      string `json:"platform"`
			Status        string `json:"status"`
		}{1, name, selected.Platform(), status})
	}
	fmt.Fprintf(stdout, "Target %s %s\n", name, status)
	return 0
}
