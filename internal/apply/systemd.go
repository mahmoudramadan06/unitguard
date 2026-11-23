package apply

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// RealSystemd drives the host's systemctl. It requires a live systemd
// (systemd as PID 1 or a user manager) and usually root.
type RealSystemd struct {
	// Systemctl is the systemctl binary path; empty uses PATH lookup.
	Systemctl string
}

func (r RealSystemd) run(ctx context.Context, args ...string) error {
	bin := r.Systemctl
	if bin == "" {
		bin = "systemctl"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (r RealSystemd) DaemonReload(ctx context.Context) error { return r.run(ctx, "daemon-reload") }

// Cat returns `systemctl cat` output for a unit (the merged unit text).
func (r RealSystemd) Cat(ctx context.Context, unit string) (string, error) {
	bin := r.Systemctl
	if bin == "" {
		bin = "systemctl"
	}
	cmd := exec.CommandContext(ctx, bin, "cat", unit)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("systemctl cat %s: %w", unit, err)
	}
	return string(out), nil
}
func (r RealSystemd) Restart(ctx context.Context, unit string) error {
	return r.run(ctx, "restart", unit)
}
func (r RealSystemd) ResetFailed(ctx context.Context, unit string) error {
	return r.run(ctx, "reset-failed", unit)
}

// Show returns the requested properties via `systemctl show`.
func (r RealSystemd) Show(ctx context.Context, unit string, props ...string) (map[string]string, error) {
	bin := r.Systemctl
	if bin == "" {
		bin = "systemctl"
	}
	args := append([]string{"show", unit, "--property"}, props...)
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	m := make(map[string]string, len(props))
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			m[k] = v
		}
	}
	return m, nil
}
func (r RealSystemd) IsActive(ctx context.Context, unit string) (bool, error) {
	bin := r.Systemctl
	if bin == "" {
		bin = "systemctl"
	}
	cmd := exec.CommandContext(ctx, bin, "is-active", unit)
	out, err := cmd.Output()
	state := strings.TrimSpace(string(out))
	if err != nil {
		// systemctl is-active exits non-zero for inactive/failed units; that is
		// a state answer, not a transport failure.
		if state == "inactive" || state == "failed" || state == "unknown" {
			return false, nil
		}
		return false, fmt.Errorf("systemctl is-active: %v: %s", err, state)
	}
	return state == "active", nil
}

// FSStore keeps drop-ins under a systemd drop-in directory.
// Root is normally /etc/systemd/system; tests point it at a temp dir.
type FSStore struct {
	Root string
}

func (s FSStore) path(unit string) string {
	return filepath.Join(s.Root, unit+".d", "override.conf")
}

func (s FSStore) Read(unit string) ([]byte, error) {
	return os.ReadFile(s.path(unit)) // os.IsNotExist propagates: no previous drop-in
}

func (s FSStore) Write(unit string, content []byte) error {
	p := s.path(unit)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, content, 0o644)
}

func (s FSStore) Remove(unit string) error {
	err := os.Remove(s.path(unit))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	// Remove the drop-in directory when it is now empty.
	_ = os.Remove(filepath.Dir(s.path(unit)))
	return nil
}

// ExecRunner runs health checks through the OS.
type ExecRunner struct {
	Timeout time.Duration
}

func (e ExecRunner) Run(ctx context.Context, argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("empty health-check command")
	}
	if e.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		trim := bytes.TrimSpace(out)
		if len(trim) > 400 {
			trim = trim[len(trim)-400:]
		}
		return fmt.Errorf("%s: %v: %s", argv[0], err, string(trim))
	}
	return nil
}

// SystemdRunGuard implements the dead-man timer with a transient systemd
// timer: if unitguard crashes or the session dies mid-apply, systemd itself
// still runs the rollback. It is armed before the restart and disarmed only
// after the service is verified healthy.
type SystemdRunGuard struct {
	// Unitguard is the unitguard binary used by the timer; empty = PATH.
	Unitguard string
	// Systemctl is the systemctl binary; empty = PATH.
	Systemctl string
}

func (g SystemdRunGuard) Arm(ctx context.Context, unit string, within time.Duration) (func(context.Context) error, error) {
	ug := g.Unitguard
	if ug == "" {
		ug = "unitguard"
	}
	name := "unitguard-deadman-" + strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, unit)
	secs := int(within.Seconds())
	if secs < 30 {
		secs = 30
	}
	cmd := exec.CommandContext(ctx, "systemd-run", "--unit", name,
		"--on-active", fmt.Sprintf("%ds", secs), ug, "rollback", "--unit", unit)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("systemd-run dead-man timer: %v: %s", err, strings.TrimSpace(string(out)))
	}
	sc := g.Systemctl
	if sc == "" {
		sc = "systemctl"
	}
	return func(dctx context.Context) error {
		// Stopping the timer cancels a pending rollback; if it already fired
		// the stop is a harmless no-op.
		cmd := exec.CommandContext(dctx, sc, "stop", name+".timer")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("disarm dead-man timer: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}, nil
}

// FSBackupStore persists pre-apply drop-in bytes under Dir (normally
// /var/lib/unitguard) so rollback survives process crashes and reboots.
type FSBackupStore struct {
	Dir string
}

func (s FSBackupStore) path(unit string) string {
	return filepath.Join(s.Dir, unit+".bak")
}

func (s FSBackupStore) Save(unit string, data []byte) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.path(unit), data, 0o600)
}

func (s FSBackupStore) Load(unit string) ([]byte, error) {
	return os.ReadFile(s.path(unit)) // os.IsNotExist propagates
}

func (s FSBackupStore) Clear(unit string) error {
	err := os.Remove(s.path(unit))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
