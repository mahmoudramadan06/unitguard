# unitguard

> **Status: experimental work in progress.** The `apply`/`rollback` path has **not been validated against a live systemd manager** — it is covered by mock-based tests and offline syntax checks only (see the testing matrix below). Do **not** run `apply` on a host or service you care about yet. The observation and generation stages (`observe`, `generate`) run locally and are safe to try.

Generate and safely apply least-privilege systemd sandboxing from observed service behavior.

`unitguard` traces what a service actually does with `strace` and turns that evidence into a systemd drop-in (`ProtectSystem`, `ReadWritePaths`, `RestrictAddressFamilies`, ...). Its apply stage is designed to be transactional: preflight health check, restart, post-checks, automatic rollback, and an independent dead-man timer that restores the previous state if `unitguard` crashes mid-apply. That apply machinery is implemented and mock-tested but **not yet validated on live systemd** — treat it as unproven until the testing matrix says otherwise.

## Why

Hardening a service by hand means guessing which of systemd's ~100 sandbox directives it can survive. Guess too tight and the service breaks at 3 AM; guess too loose and the sandbox is decoration. `unitguard` starts from evidence instead: what the service opened, wrote, executed and connected to during a real run.

## Install

Requires Go 1.22+ and, for applying, a Linux host running systemd with root.

```
go install github.com/mahmoudramadan06/unitguard/cmd/unitguard@latest
```

Runtime requirements: `strace` for `observe` (tracing a system service's processes also needs root or ptrace permission), `systemctl` for `apply`/`rollback`, `systemd-analyze` for `verify`.

## Usage

```
# 1. Trace the service's command (or any command) and record what it does.
#    observe runs the command itself under strace for the duration;
#    it does not attach to or restart the running service.
unitguard observe --unit myapp.service --duration 30s --out obs.json
unitguard observe --cmd "/usr/local/bin/myapp --serve" --out obs.json

# 2. Generate the drop-in, with reasons and warnings
unitguard generate --unit myapp.service --observation obs.json

# 3. Apply it: preflight health check -> restart -> verify -> auto-rollback on failure
unitguard apply --unit myapp.service --observation obs.json --health-check "curl -fs localhost:8080/health"

# Undo
unitguard rollback --unit myapp.service

# Lint a file offline, or a live unit's merged definition, with systemd's own checker
unitguard verify --dropin override.conf
unitguard verify --unit myapp.service --security
```

Opt-in flags (off by default because a trace cannot prove they are safe): `--drop-caps` emits an empty `CapabilityBoundingSet`; `--remove-ipc` emits `RemoveIPC=true`; `--private-devices` emits `PrivateDevices=true`. `--allow-late-network` is a *relaxation*: it keeps IPv4/IPv6 allowed even when the trace saw no sockets, for services that bind only on demand.

## What it generates (and what it deliberately doesn't)

Every directive is emitted with a plain-English note, and every risky judgment call becomes a warning you must review. Defaults are conservative:

- `ProtectSystem=strict` with `ReadWritePaths` limited to observed write prefixes. Writes under `/usr`, `/boot`, `/` downgrade to `ProtectSystem=full` with a loud warning instead of a broad grant; `/etc` subtrees are granted specifically.
- `RestrictAddressFamilies` limited to observed families plus `AF_UNIX`. `AF_NETLINK` rides along with IP families because name resolution needs it.
- `PrivateTmp` is skipped (with a warning) when `/tmp` writes were observed; shared-`/tmp` services would break.
- `NoNewPrivileges`, `RestrictSUIDSGID`, kernel/log/clock/cgroup protections, `LockPersonality`, `RestrictRealtime` are on by default (no-regret tier).
- Capabilities are **not** dropped by default: strace cannot see a capability a service needs only occasionally. `--drop-caps` is there once you have load-tested.
- Never generated: `SystemCallFilter` allow-lists from strace (a missed call is a SIGSYS kill), `IPAddressAllow` (DNS is dynamic).

A generated drop-in passes a soundness check before it is emitted: the checker is implemented independently of the synthesis code and refuses to print a drop-in that would block *observed* behavior. Its independence is from the generator's code, not from the evidence — if the trace missed behavior, both share that blind spot.

## Apply safety model

1. **Preflight**: `systemctl show` baseline (`ActiveState`, `NRestarts`); your health check must pass on the *unmodified* service first, otherwise a post-apply failure proves nothing.
2. **Dead-man timer**: `systemd-run` schedules an independent `unitguard rollback` before the restart, disarmed only after the service is verified healthy. It survives unitguard crashing or an SSH drop, but **not a host reboot** (transient units are gone after one) — a reboot mid-apply leaves the new drop-in in place.
3. **Transactional apply**: snapshot existing drop-in → write → `daemon-reload` → restart → settle → `is-active` → `NRestarts` must not move (catches crash-loops that `Restart=always` hides; the exact `NRestarts` semantics are systemd-version-dependent and part of what live validation still needs to confirm) → your health check.
4. **Rollback**: restores the pre-apply drop-in bytes, persisted at apply time under `/var/lib/unitguard/` so rollback still works from a new process (dead-man timer, manual run, after a crash); removes the drop-in when none existed. Then `reset-failed` (a start-limit hit would block the restart), reload, restart, active-check. `unitguard rollback --unit X` does the same by hand.

Only the file `<unit>.d/override.conf` is managed; other drop-ins in the same directory are left untouched.

## Testing status — read this before trusting it

What has actually been executed (not just claimed):

| Layer | Status |
|---|---|
| Unit tests: trace parser, ExecStart parser, policy synthesis, apply/rollback state machine (fake systemd), soundness checker | **Passing** (`go test ./...`) |
| Real end-to-end offline pipeline: `observe` on a live traced process → `generate` → `systemd-analyze verify` accepting the result | **Passing** (systemd 249; this is a *syntax* check — it does not prove the service tolerates the directives) |
| Apply/rollback against a **live systemd** (real restart, real dead-man timer, real rollback) | **Not yet tested** — needs a real Linux host or VM with systemd as PID 1 |
| `systemd-analyze security` scoring | Not exercised; needs systemd ≥ 250 or a live bus |

The fake-systemd tests cover restart failure, inactive service, health failure, flapping detection, preflight abort, drop-in restoration and the guard arm/disarm — but they prove the state machine, not real systemd behavior. Directive semantics (`ReadWritePaths` under `strict`, drop-in reset behavior, start-limit handling) are modeled from the man pages, not yet confirmed on a live manager. **Run `apply` on a non-critical service first.**

The observation model has inherent blind spots: strace only sees code paths exercised during the trace, and its ptrace overhead slows the process, which can mask timing-dependent behavior. Re-run `observe` under realistic load, exercise reload/logrotation/failure paths while tracing, and treat the first days under a new drop-in as a soak period. A single health check right after restart cannot catch delayed failures (log rotation, DNS changes, cron-like paths).

## Design notes

Pipeline: `strace → Observation (JSON) → policy synthesis → drop-in → soundness check → transactional apply`. The parser, policy engine and checker are pure packages with no host I/O; all host access sits behind small interfaces (`Systemd`, `DropinStore`, `Runner`, `Guard`) with fakes for tests.

Built with a multi-model workflow: architecture and risk review (Claude), directive-mapping safety review (DeepSeek), the independent soundness checker (OpenCode), documentation and final review passes (Z.ai, Gemini), integration and testing by the author. Details and divergences are in `docs/ai-workflow.md`.

## License

MIT — see [LICENSE](LICENSE).
