# unitguard

Generate and safely apply least-privilege systemd sandboxing from observed service behavior.

`unitguard` traces what a service actually does with `strace`, turns that evidence into a systemd drop-in (`ProtectSystem`, `ReadWritePaths`, `RestrictAddressFamilies`, ...), and applies it transactionally: preflight health check, restart, post-checks, automatic rollback, and an independent dead-man timer that restores the previous state even if `unitguard` itself crashes mid-apply.

## Why

Hardening a service by hand means guessing which of systemd's ~100 sandbox directives it can survive. Guess too tight and the service breaks at 3 AM; guess too loose and the sandbox is decoration. `unitguard` starts from evidence instead: what the service opened, wrote, executed and connected to during a real run.

## Install

Requires Go 1.22+ and, for applying, a Linux host running systemd with root.

```
go install github.com/mahmoudramadan06/unitguard/cmd/unitguard@latest
```

Runtime requirements: `strace` for `observe`, `systemctl` for `apply`/`rollback`, `systemd-analyze` for `verify`.

## Usage

```
# 1. Trace the service (or any command) and record what it does
unitguard observe --unit myapp.service --duration 30s --out obs.json
unitguard observe --cmd "/usr/local/bin/myapp --serve" --out obs.json

# 2. Generate the drop-in, with reasons and warnings
unitguard generate --unit myapp.service --observation obs.json

# 3. Apply it: preflight health check -> restart -> verify -> auto-rollback on failure
unitguard apply --unit myapp.service --observation obs.json --health-check "curl -fs localhost:8080/health"

# Undo
unitguard rollback --unit myapp.service

# Lint a unit with systemd's own checker
unitguard verify --unit myapp.service
```

Opt-in hardening (off by default because a trace cannot prove they are safe): `--drop-caps` (empty `CapabilityBoundingSet`), `--remove-ipc`, `--private-devices`, `--allow-late-network`.

## What it generates (and what it deliberately doesn't)

Every directive is emitted with a plain-English note, and every risky judgment call becomes a warning you must review. Defaults are conservative:

- `ProtectSystem=strict` with `ReadWritePaths` limited to observed write prefixes. Writes under `/usr`, `/boot`, `/` downgrade to `ProtectSystem=full` with a loud warning instead of a broad grant; `/etc` subtrees are granted specifically.
- `RestrictAddressFamilies` limited to observed families plus `AF_UNIX`. `AF_NETLINK` rides along with IP families because name resolution needs it.
- `PrivateTmp` is skipped (with a warning) when `/tmp` writes were observed; shared-`/tmp` services would break.
- `NoNewPrivileges`, `RestrictSUIDSGID`, kernel/log/clock/cgroup protections, `LockPersonality`, `RestrictRealtime` are on by default (no-regret tier).
- Capabilities are **not** dropped by default: strace cannot see a capability a service needs only occasionally. `--drop-caps` is there once you have load-tested.
- Never generated: `SystemCallFilter` allow-lists from strace (a missed call is a SIGSYS kill), `IPAddressAllow` (DNS is dynamic).

A generated drop-in passes an independent soundness check before it is emitted: the checker re-derives coverage from the observation and refuses to print a drop-in that would block observed behavior.

## Apply safety model

1. **Preflight**: `systemctl show` baseline (`ActiveState`, `NRestarts`); your health check must pass on the *unmodified* service first, otherwise a post-apply failure proves nothing.
2. **Dead-man timer**: `systemd-run` schedules an independent `unitguard rollback` before the restart. If the machine loses unitguard (crash, SSH drop), systemd still restores the service. Disarmed only after the service is verified healthy.
3. **Transactional apply**: snapshot existing drop-in → write → `daemon-reload` → restart → settle → `is-active` → `NRestarts` must not move (catches crash-loops that `Restart=always` hides) → your health check.
4. **Rollback**: restores the previous drop-in bytes exactly (or removes it), `reset-failed` (a start-limit hit would block the restart), reload, restart, active-check. `unitguard rollback --unit X` does the same by hand.

## Testing status — read this before trusting it

What has actually been executed (not just claimed):

| Layer | Status |
|---|---|
| Unit tests: trace parser, ExecStart parser, policy synthesis, apply/rollback state machine (fake systemd), soundness checker | **Passing** (`go test ./...`) |
| Real end-to-end offline pipeline: `observe` on a live traced process → `generate` → `systemd-analyze verify` accepting the result | **Passing** (systemd 249) |
| Apply/rollback against a **live systemd** (real restart, real dead-man timer, real rollback) | **Not yet tested** — needs a real Linux host or VM with systemd as PID 1 |
| `systemd-analyze security` scoring | Not exercised; needs systemd ≥ 250 or a live bus |

The fake-systemd tests cover restart failure, inactive service, health failure, flapping detection, preflight abort, drop-in restoration and the guard arm/disarm — but they prove the state machine, not real systemd behavior. Directive semantics (`ReadWritePaths` under `strict`, drop-in reset behavior, start-limit handling) are modeled from the man pages, not yet confirmed on a live manager. **Run `apply` on a non-critical service first.**

The observation model has an inherent blind spot: strace only sees code paths exercised during the trace. Re-run `observe` under realistic load, use `--exercise`-style commands that hit reload/logrotation paths, and treat the first days under a new drop-in as a soak period.

## Design notes

Pipeline: `strace → Observation (JSON) → policy synthesis → drop-in → soundness check → transactional apply`. The parser, policy engine and checker are pure packages with no host I/O; all host access sits behind small interfaces (`Systemd`, `DropinStore`, `Runner`, `Guard`) with fakes for tests.

Built with a multi-model workflow: architecture and risk review (Claude), directive-mapping safety review (DeepSeek), the independent soundness checker (OpenCode), documentation and final review passes (Z.ai, Gemini), integration and testing by the author. Details and divergences are in `docs/ai-workflow.md`.

## License

MIT — see [LICENSE](LICENSE).
