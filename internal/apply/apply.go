// Package apply writes a generated drop-in and restarts the unit, with
// automatic rollback when the hardened service fails to come up healthy.
//
// Safety model (from the architecture review):
//   - preflight: the health check must pass on the unmodified service first,
//     otherwise a failure after apply cannot be attributed to the drop-in;
//   - baseline: ActiveState and NRestarts are recorded before the change;
//     NRestarts must not move after apply (Restart=always masks flapping);
//   - transactional: snapshot -> write -> daemon-reload -> restart -> settle
//     -> verify -> commit, with restore-on-failure at every step;
//   - dead-man timer: on a real host an optional Guard schedules an
//     independent rollback (systemd-run) that survives a crash of unitguard
//     or a dropped SSH session, and is disarmed only after commit;
//   - rollback restores the previous drop-in bytes exactly, runs
//     reset-failed (a start-limit hit would block the restart otherwise),
//     reloads and restarts, then re-checks health.
package apply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

// Systemd is the host surface the Applier needs. Fakes implement it in tests.
type Systemd interface {
	DaemonReload(ctx context.Context) error
	Restart(ctx context.Context, unit string) error
	ResetFailed(ctx context.Context, unit string) error
	IsActive(ctx context.Context, unit string) (bool, error)
	// Show returns the requested properties of the unit
	// (e.g. ActiveState, NRestarts).
	Show(ctx context.Context, unit string, props ...string) (map[string]string, error)
}

// DropinStore persists the drop-in file.
type DropinStore interface {
	Read(unit string) ([]byte, error) // os.IsNotExist when absent
	Write(unit string, data []byte) error
	Remove(unit string) error
}

// Runner executes the user-supplied health check.
type Runner interface {
	Run(ctx context.Context, argv []string) error
}

// Guard arms an out-of-process rollback safety net (dead-man timer). It is
// optional: when nil, rollback depends on unitguard itself surviving.
type Guard interface {
	// Arm schedules an independent rollback of unit within the budget.
	// The returned disarm function cancels it after a successful commit.
	Arm(ctx context.Context, unit string, within time.Duration) (disarm func(context.Context) error, err error)
}

// BackupStore persists the pre-apply drop-in bytes so rollback still
// restores them after unitguard crashes or the host reboots (the dead-man
// timer and manual rollback run in a new process with no in-memory
// snapshot). os.IsNotExist from Load means no previous drop-in existed.
type BackupStore interface {
	Save(unit string, data []byte) error
	Load(unit string) ([]byte, error)
	Clear(unit string) error
}

type Applier struct {
	Systemd Systemd
	Store   DropinStore
	Health  Runner      // optional: nil skips user health checks
	Guard   Guard       // optional: nil disables the dead-man timer
	Backup  BackupStore // optional: nil keeps rollback snapshots in memory only
	Settle  time.Duration

	prev    []byte // snapshot of the previous drop-in, for rollback
	hadPrev bool
}

type Result struct {
	Applied        bool
	RolledBack     bool
	RollbackFailed bool
}

// Apply installs dropin for unit and restarts it. On any verification
// failure the previous state is restored automatically.
func (a *Applier) Apply(ctx context.Context, unit string, dropin []byte, healthArgv []string) (Result, error) {
	var res Result

	// Baseline before touching anything.
	base, err := a.Systemd.Show(ctx, unit, "ActiveState", "NRestarts")
	if err != nil {
		return res, fmt.Errorf("preflight: read unit state: %w", err)
	}
	if base["ActiveState"] == "" {
		return res, fmt.Errorf("preflight: unit %q not loaded", unit)
	}
	baseRestarts := base["NRestarts"]

	// Preflight health: the check must pass before the change so a later
	// failure is attributable to the drop-in.
	if len(healthArgv) > 0 && a.Health != nil {
		if err := a.Health.Run(ctx, healthArgv); err != nil {
			return res, fmt.Errorf("preflight: health check already fails on the unmodified service, aborting: %w", err)
		}
	}

	// Arm the dead-man timer when configured.
	var disarm func(context.Context) error
	if a.Guard != nil {
		d, err := a.Guard.Arm(ctx, unit, a.budget())
		if err != nil {
			return res, fmt.Errorf("arm dead-man timer: %w", err)
		}
		disarm = d
	}

	fail := func(cause error) (Result, error) {
		res.RolledBack = true
		if rbErr := a.rollback(ctx, unit); rbErr != nil {
			res.RollbackFailed = true
			return res, errors.Join(cause, fmt.Errorf("rollback failed: %w", rbErr))
		}
		return res, cause
	}

	if err := a.writeDropin(unit, dropin); err != nil {
		return res, fmt.Errorf("write drop-in: %w", err) // nothing restarted yet; no rollback needed
	}
	if err := a.Systemd.DaemonReload(ctx); err != nil {
		return fail(fmt.Errorf("daemon-reload: %w", err))
	}
	if err := a.Systemd.Restart(ctx, unit); err != nil {
		return fail(fmt.Errorf("restart: %w", err))
	}
	if a.Settle > 0 {
		select {
		case <-ctx.Done():
			return fail(ctx.Err())
		case <-time.After(a.Settle):
		}
	}
	active, err := a.Systemd.IsActive(ctx, unit)
	if err != nil {
		return fail(fmt.Errorf("check active: %w", err))
	}
	if !active {
		return fail(errors.New("service is not active after hardening"))
	}

	// Flapping detection: Restart=always would keep a crash-looping service
	// "active" at observation time, so NRestarts must not have moved.
	post, err := a.Systemd.Show(ctx, unit, "NRestarts")
	if err != nil {
		return fail(fmt.Errorf("re-read unit state: %w", err))
	}
	if post["NRestarts"] != baseRestarts {
		return fail(fmt.Errorf("NRestarts moved %s -> %s: service is flapping under the new policy", baseRestarts, post["NRestarts"]))
	}

	if len(healthArgv) > 0 && a.Health != nil {
		if err := a.Health.Run(ctx, healthArgv); err != nil {
			return fail(fmt.Errorf("health check: %w", err))
		}
	}

	if disarm != nil {
		if err := disarm(ctx); err != nil {
			return fail(fmt.Errorf("disarm dead-man timer: %w", err))
		}
	}
	res.Applied = true
	return res, nil
}

// Rollback restores the pre-apply state and restarts the unit: the
// persisted backup when one exists, otherwise removal of the drop-in.
func (a *Applier) Rollback(ctx context.Context, unit string) error {
	if a.Backup != nil {
		prev, err := a.Backup.Load(unit)
		switch {
		case err == nil:
			if err := a.Store.Write(unit, prev); err != nil {
				return fmt.Errorf("restore backed-up drop-in: %w", err)
			}
			return a.reloadRestart(ctx, unit)
		case !os.IsNotExist(err):
			return fmt.Errorf("read drop-in backup: %w", err)
		}
	}
	if err := a.Store.Remove(unit); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove drop-in: %w", err)
	}
	return a.reloadRestart(ctx, unit)
}

func (a *Applier) budget() time.Duration {
	return 2*time.Minute + a.Settle
}

func (a *Applier) writeDropin(unit string, dropin []byte) error {
	prev, err := a.Store.Read(unit)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("snapshot existing drop-in: %w", err)
	}
	// Keep the snapshot for rollback inside this process, and persist it so
	// a later process (dead-man timer, manual rollback, after a crash or
	// reboot) restores the same bytes.
	a.prev, a.hadPrev = prev, err == nil
	if a.Backup != nil {
		if a.hadPrev {
			if err := a.Backup.Save(unit, prev); err != nil {
				return fmt.Errorf("persist drop-in backup: %w", err)
			}
		} else if err := a.Backup.Clear(unit); err != nil {
			return fmt.Errorf("clear stale drop-in backup: %w", err)
		}
	}
	return a.Store.Write(unit, dropin)
}

func (a *Applier) rollback(ctx context.Context, unit string) error {
	// Rollback must finish even when the caller's context is canceled
	// (e.g. SIGINT mid-apply): detach it, with its own deadline.
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	if a.hadPrev {
		if err := a.Store.Write(unit, a.prev); err != nil {
			return err
		}
	} else if err := a.Store.Remove(unit); err != nil && !os.IsNotExist(err) {
		return err
	}
	return a.reloadRestart(ctx, unit)
}

// reloadRestart reloads systemd and restarts the unit. reset-failed runs
// first: a start-limit hit would otherwise refuse the restart.
func (a *Applier) reloadRestart(ctx context.Context, unit string) error {
	if err := a.Systemd.ResetFailed(ctx, unit); err != nil {
		return fmt.Errorf("reset-failed: %w", err)
	}
	if err := a.Systemd.DaemonReload(ctx); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	}
	if err := a.Systemd.Restart(ctx, unit); err != nil {
		return fmt.Errorf("restart: %w", err)
	}
	active, err := a.Systemd.IsActive(ctx, unit)
	if err != nil {
		return err
	}
	if !active {
		return errors.New("service did not come back after rollback")
	}
	return nil
}
