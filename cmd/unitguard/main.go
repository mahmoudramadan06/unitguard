// unitguard generates least-privilege systemd drop-ins from observed
// service behavior and applies them with automatic rollback.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mahmoudramadan06/unitguard/internal/apply"
	"github.com/mahmoudramadan06/unitguard/internal/policy"
	"github.com/mahmoudramadan06/unitguard/internal/trace"
	"github.com/mahmoudramadan06/unitguard/internal/unit"
	"github.com/mahmoudramadan06/unitguard/internal/verify"
)

const usage = `unitguard - generate and safely apply least-privilege systemd sandboxing

Usage:
  unitguard observe  --unit NAME [--duration 30s] [--cmd "command args"] [--out obs.json]
  unitguard generate [--unit NAME] [--observation obs.json] [--out override.conf]
  unitguard apply    --unit NAME [--observation obs.json] [--health-check "cmd"] [--yes]
  unitguard rollback --unit NAME
  unitguard verify   --unit NAME [--dropin path]

observe traces the service's ExecStart (or --cmd) with strace and records
what it actually does. generate turns that observation into a drop-in.
apply writes the drop-in, restarts the service, health-checks it and rolls
back automatically on failure. rollback removes the drop-in. verify runs
systemd-analyze on the result.

apply and rollback need root and a live systemd. observe needs strace.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "observe":
		err = cmdObserve(os.Args[2:])
	case "generate":
		err = cmdGenerate(os.Args[2:])
	case "apply":
		err = cmdApply(os.Args[2:])
	case "rollback":
		err = cmdRollback(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "unitguard:", err)
		os.Exit(1)
	}
}

func loadObservation(path string) (trace.Observation, error) {
	var obs trace.Observation
	b, err := os.ReadFile(path)
	if err != nil {
		return obs, err
	}
	return obs, json.Unmarshal(b, &obs)
}

func saveObservation(path string, obs trace.Observation) error {
	b, err := json.MarshalIndent(obs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func cmdObserve(args []string) error {
	fs := flag.NewFlagSet("observe", flag.ContinueOnError)
	unitName := fs.String("unit", "", "systemd unit to trace (uses its ExecStart)")
	cmdStr := fs.String("cmd", "", "command to trace instead of a unit")
	dur := fs.Duration("duration", 30*time.Second, "how long to observe before stopping the trace")
	out := fs.String("out", "", "write observation JSON here (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()

	var argv []string
	switch {
	case *cmdStr != "":
		argv = strings.Fields(*cmdStr)
	case *unitName != "":
		text, err := (apply.RealSystemd{}).Cat(ctx, *unitName)
		if err != nil {
			return err
		}
		cmds, err := unit.ParseExecStart(strings.NewReader(text))
		if err != nil {
			return err
		}
		if len(cmds) == 0 {
			return fmt.Errorf("unit %s has no ExecStart", *unitName)
		}
		if specs := cmds[0].UnexpandedSpecifiers; len(specs) > 0 {
			return fmt.Errorf("ExecStart contains unexpanded specifiers %v; use --cmd with the real command line", specs)
		}
		argv = cmds[0].Argv
	default:
		return fmt.Errorf("give --unit or --cmd")
	}

	fmt.Fprintf(os.Stderr, "tracing: %s (up to %s)\n", strings.Join(argv, " "), *dur)
	obs, err := trace.Run(ctx, argv, *dur)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "observed: %s\n", obs)
	if *out == "" {
		b, _ := json.MarshalIndent(obs, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	return saveObservation(*out, obs)
}

func cmdGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	unitName := fs.String("unit", "", "unit name (used in the header comment)")
	obsPath := fs.String("observation", "", "observation JSON from `unitguard observe`")
	out := fs.String("out", "", "write drop-in here (default stdout)")
	lateNet := fs.Bool("allow-late-network", false, "allow IPv4/IPv6 even if no socket was observed")
	privDev := fs.Bool("private-devices", false, "also hide physical /dev devices")
	dropCaps := fs.Bool("drop-caps", false, "empty CapabilityBoundingSet (strong; load-test first)")
	removeIPC := fs.Bool("remove-ipc", false, "remove SysV/POSIX IPC objects on stop")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *obsPath == "" {
		return fmt.Errorf("give --observation obs.json from `unitguard observe`")
	}
	obs, err := loadObservation(*obsPath)
	if err != nil {
		return err
	}
	dec := policy.Synthesize(obs, policy.Options{AllowLateNetwork: *lateNet, PrivateDevices: *privDev, DropCaps: *dropCaps, RemoveIPC: *removeIPC})
	if err := soundnessGate(obs, dec); err != nil {
		return err
	}
	text := policy.Render(dec)
	if *unitName != "" {
		text = "# unitguard drop-in for " + *unitName + "\n" + text
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(text), 0o644); err != nil {
			return err
		}
	} else {
		fmt.Print(text)
	}
	for _, n := range dec.Notes {
		fmt.Fprintln(os.Stderr, "note:", n)
	}
	for _, w := range dec.Warnings {
		fmt.Fprintln(os.Stderr, "WARNING:", w)
	}
	return nil
}

func cmdApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	unitName := fs.String("unit", "", "systemd unit to sandbox (required)")
	obsPath := fs.String("observation", "", "observation JSON; if empty, reuse existing drop-in on disk check only")
	dropinPath := fs.String("dropin", "", "ready drop-in file to apply instead of generating")
	health := fs.String("health-check", "", "command that must exit 0 after restart")
	settle := fs.Duration("settle", 2*time.Second, "wait after restart before checking state")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *unitName == "" {
		return fmt.Errorf("give --unit")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("apply needs root (writes /etc/systemd/system and restarts services)")
	}

	var dropin []byte
	switch {
	case *dropinPath != "":
		b, err := os.ReadFile(*dropinPath)
		if err != nil {
			return err
		}
		dropin = b
	case *obsPath != "":
		obs, err := loadObservation(*obsPath)
		if err != nil {
			return err
		}
		dec := policy.Synthesize(obs, policy.Options{})
		if err := soundnessGate(obs, dec); err != nil {
			return err
		}
		dropin = []byte(policy.Render(dec))
		for _, w := range dec.Warnings {
			fmt.Fprintln(os.Stderr, "WARNING:", w)
		}
	default:
		return fmt.Errorf("give --observation or --dropin")
	}

	if !*yes {
		fmt.Printf("About to sandbox %s and restart it. Drop-in:\n%s\nContinue? [y/N] ", *unitName, dropin)
		var answer string
		fmt.Scanln(&answer)
		if !strings.EqualFold(strings.TrimSpace(answer), "y") {
			return fmt.Errorf("aborted")
		}
	}

	a := &apply.Applier{
		Systemd: apply.RealSystemd{},
		Store:   apply.FSStore{Root: "/etc/systemd/system"},
		Health:  apply.ExecRunner{Timeout: 30 * time.Second},
		Guard:   apply.SystemdRunGuard{},
		Settle:  *settle,
	}
	var healthArgv []string
	if *health != "" {
		healthArgv = strings.Fields(*health)
	}
	res, err := a.Apply(context.Background(), *unitName, dropin, healthArgv)
	switch {
	case err != nil && res.RollbackFailed:
		return fmt.Errorf("CRITICAL: %w", err)
	case err != nil:
		return err
	}
	fmt.Println("applied: service restarted with the new drop-in and passed its checks")
	return nil
}

func cmdRollback(args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	unitName := fs.String("unit", "", "systemd unit to restore (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *unitName == "" {
		return fmt.Errorf("give --unit")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("rollback needs root")
	}
	a := &apply.Applier{Systemd: apply.RealSystemd{}, Store: apply.FSStore{Root: "/etc/systemd/system"}}
	if err := a.Rollback(context.Background(), *unitName); err != nil {
		return err
	}
	fmt.Println("rolled back: drop-in removed, service restarted")
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	unitName := fs.String("unit", "", "unit name on a live systemd")
	dropin := fs.String("dropin", "", "drop-in file to lint with systemd-analyze verify")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	an := verify.Analyzer{}
	if *dropin != "" {
		report, err := an.Lint(ctx, *dropin)
		if report != "" {
			fmt.Println(report)
		}
		if err != nil {
			return fmt.Errorf("systemd-analyze verify: %w", err)
		}
		fmt.Println("verify: systemd-analyze accepted the file")
	}
	if *unitName != "" {
		score, raw, err := an.SecurityScore(ctx, *unitName)
		if err != nil {
			return fmt.Errorf("%w\n%s", err, raw)
		}
		fmt.Printf("current exposure level for %s: %.1f (lower is better)\n", *unitName, score)
	}
	if *dropin == "" && *unitName == "" {
		return fmt.Errorf("give --unit and/or --dropin")
	}
	return nil
}

// soundnessGate runs the independent coverage check on the generator's own
// output. A violation means a generator bug, so it is a hard failure: the
// drop-in must never be emitted or applied.
func soundnessGate(obs trace.Observation, dec policy.Decision) error {
	var rwPaths, families []string
	downgrade := false
	familiesSet := false
	for _, d := range dec.Directives {
		switch d.Key {
		case "ReadWritePaths":
			rwPaths = strings.Fields(d.Value)
		case "RestrictAddressFamilies":
			families = strings.Fields(d.Value)
			familiesSet = true
		case "ProtectSystem":
			downgrade = d.Value == "full"
		}
	}
	if !familiesSet {
		families = nil
	}
	if v := verify.Covers(obs, rwPaths, families, downgrade); len(v) > 0 {
		return fmt.Errorf("soundness check failed, refusing to emit drop-in: %s", strings.Join(v, "; "))
	}
	return nil
}
