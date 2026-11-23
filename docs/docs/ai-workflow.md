# How unitguard was built: multi-model workflow

unitguard was built by a human-directed workflow that split work across
several AI assistants, each with a bounded assignment. Every contribution was
reviewed, integrated and tested by the maintainer. No AI-generated code was
merged without local tests executing against it.

## Who did what

| Assistant | Assignment | Outcome |
|---|---|---|
| Claude (Sonnet) | Architecture + risk analysis: package layout, riskiest design decisions, work division, test strategy | Adopted: preflight health check, baseline `NRestarts` flapping detection, dead-man timer, `reset-failed` in rollback, `/var/run` canonicalization, tiered directive model, soundness-checker independence. Deferred (documented as future work): evidence-tiered profile package, write-ahead journal, `/proc` capability sampling, `--exercise`, soak mode |
| DeepSeek | Safety review of the directive mapping (`internal/policy/policy.go`) | Found real issues, adopted: `AF_NETLINK` must ride with IP families (name resolution); unconditional empty `CapabilityBoundingSet` breaks low-port/setuid daemons (now opt-in `--drop-caps`); `RemoveIPC` unconditional is unsafe because IPC is outside traced syscall classes (now opt-in); `PrivateTmp` vs observed `/tmp` writes (now skipped with warning); `/etc` writes forced a downgrade yet were never granted (now granted via `ReadWritePaths`). Considered and not adopted: gating `LockPersonality`/`RestrictRealtime` on observation — kept in the no-regret tier per the architecture review |
| OpenCode | Implement the independent soundness checker `internal/verify/covers.go` + tests from a written contract | Delivered; integrated after adding the API-pseudo-device rule (`/dev/null` etc. need no `ReadWritePaths` under `ProtectSystem`). All its table tests run in `go test ./...` |
| Z.ai (GLM) | README / test-plan critique | Pending at publication time |
| Gemini | Final whole-repo review | Pending at publication time |

## Testing ownership

All tests were executed locally by the maintainer (`go test ./...`, plus a
real `observe → generate → systemd-analyze verify` pipeline run on a live
traced process). AI-reported results were never trusted without a local
re-run. The apply/rollback loop is covered by fake-systemd tests only; live
systemd lifecycle testing is explicitly open (see README's testing matrix).

## Privacy boundary

Only new-project code and anonymized design questions were shared with
external assistants. No personal data, credentials, private repositories or
host details were included in any prompt.
