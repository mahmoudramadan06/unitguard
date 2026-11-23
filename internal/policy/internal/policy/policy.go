// Package policy maps an observed behavior profile to least-privilege
// systemd sandboxing directives, with a plain-English reason for each choice.
package policy

import (
	"fmt"
	"strings"

	"github.com/mahmoudramadan06/unitguard/internal/trace"
)

// Directive is one key=value line in the [Service] section of a drop-in.
type Directive struct {
	Key   string
	Value string
}

// Decision is the result of synthesis: the directives to write, why each
// group was chosen, and warnings a human should review before applying.
type Decision struct {
	Directives []Directive
	Notes      []string
	Warnings   []string
}

// Options tunes synthesis. Zero value is the recommended safe default.
type Options struct {
	// AllowLateNetwork keeps AF_INET/AF_INET6 even when no socket was
	// observed, for services that bind only on demand.
	AllowLateNetwork bool
	// PrivateDevices also hides physical devices in /dev (breaks services
	// that touch real hardware).
	PrivateDevices bool
	// DropCaps empties CapabilityBoundingSet. Off by default: a strace run
	// cannot see capabilities a service only needs occasionally (low-port
	// binds, chown, setuid drops), so this is opt-in hardening.
	DropCaps bool
	// RemoveIPC removes SysV/POSIX IPC objects on stop. Off by default:
	// IPC calls are outside the traced syscall classes, so absence of
	// evidence is not evidence of absence here.
	RemoveIPC bool
}

// dangerousWritePrefixes are write roots too broad to expose read-write;
// observing one downgrades ProtectSystem instead of granting them.
// /etc is deliberately absent: ProtectSystem=full makes /etc read-only, but
// a specific /etc subtree can still be granted through ReadWritePaths, so
// /etc writes are routed there instead of forcing a downgrade.
var dangerousWritePrefixes = []string{"/", "/usr", "/bin", "/sbin", "/lib", "/boot"}

// homePrefixes route ProtectHome instead of ProtectSystem coverage.
var homePrefixes = []string{"/home", "/root"}

// pseudoDevices stay writable through the private /dev tmpfs that systemd
// always populates, so a service writing to them must not make all of /dev
// read-write.
var pseudoDevices = []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty"}

func isPseudoDevice(path string) bool {
	for _, d := range pseudoDevices {
		if path == d {
			return true
		}
	}
	return false
}

func hasPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// Synthesize converts an Observation into a sandboxing Decision.
func Synthesize(o trace.Observation, opts Options) Decision {
	var d Decision
	// Drop pseudo-device writes before prefix collapsing: /dev/null must not
	// turn into a read-write /dev.
	filtered := make([]string, 0, len(o.Writes))
	for _, w := range o.Writes {
		if !isPseudoDevice(w) {
			filtered = append(filtered, w)
		}
	}
	o.Writes = filtered
	writes := trace.WritePrefixes(o)

	broad, normal, home := partitionWrites(writes)

	// Filesystem protection.
	if len(broad) > 0 {
		d.Directives = append(d.Directives, Directive{"ProtectSystem", "full"})
		d.Warnings = append(d.Warnings, fmt.Sprintf(
			"service writes under %s; ProtectSystem downgraded to full (read-only /usr and /boot only). Review whether those writes are required.", strings.Join(broad, ", ")))
	} else {
		d.Directives = append(d.Directives, Directive{"ProtectSystem", "strict"})
	}
	if len(normal) > 0 {
		d.Directives = append(d.Directives, Directive{"ReadWritePaths", strings.Join(normal, " ")})
		d.Notes = append(d.Notes, "ProtectSystem=strict makes the whole tree read-only except these observed write paths.")
	} else if len(broad) == 0 {
		d.Notes = append(d.Notes, "no writes observed: entire filesystem is read-only to the service.")
	}
	if len(home) > 0 {
		d.Directives = append(d.Directives, Directive{"ProtectHome", "read-only"})
		d.Notes = append(d.Notes, "home directories stay readable; observed home writes are covered by ReadWritePaths.")
	} else {
		d.Directives = append(d.Directives, Directive{"ProtectHome", "true"})
		d.Notes = append(d.Notes, "no home-directory use observed: /home, /root and /run/user are hidden.")
	}
	// PrivateTmp remaps /tmp, which breaks services that share /tmp with
	// peers; observed /tmp writes are the tell.
	tmpUsed := hasPrefixIn(normal, "/tmp") || hasPrefixIn(normal, "/var/tmp")
	if tmpUsed {
		d.Warnings = append(d.Warnings, "service writes under /tmp or /var/tmp; PrivateTmp skipped so the observed paths stay valid. Shared-/tmp designs (sockets, lock files) need the real /tmp.")
	} else {
		d.Directives = append(d.Directives, Directive{"PrivateTmp", "true"})
		d.Notes = append(d.Notes, "PrivateTmp gives the service its own /tmp namespace.")
	}

	// Privilege boundaries.
	d.Directives = append(d.Directives, Directive{"NoNewPrivileges", "true"})
	d.Notes = append(d.Notes, "NoNewPrivileges blocks gaining new privileges through setuid/file capabilities.")
	if opts.DropCaps {
		d.Directives = append(d.Directives, Directive{"CapabilityBoundingSet", ""})
		d.Notes = append(d.Notes, "all capabilities dropped: the observed run needed none of the privileged operations they gate. Re-run observe if the service later fails with EPERM.")
	} else {
		d.Notes = append(d.Notes, "capabilities left at the unit's defaults: a trace cannot prove a service never needs CAP_NET_BIND_SERVICE, CAP_CHOWN or setuid drops. Use --drop-caps for stronger hardening after load testing.")
	}
	d.Directives = append(d.Directives, Directive{"RestrictSUIDSGID", "true"})

	// Network.
	fams := map[string]bool{}
	for _, f := range o.Families {
		fams[f] = true
	}
	allowed := []string{"AF_UNIX"}
	if fams["AF_INET"] || fams["AF_INET6"] || opts.AllowLateNetwork {
		allowed = append(allowed, "AF_INET", "AF_INET6")
		// Name resolution and NSS paths use netlink; allowing IP without it
		// breaks getaddrinfo at runtime even when the trace saw none.
		allowed = append(allowed, "AF_NETLINK")
	} else if fams["AF_NETLINK"] {
		allowed = append(allowed, "AF_NETLINK")
	}
	if fams["AF_PACKET"] {
		allowed = append(allowed, "AF_PACKET")
		d.Warnings = append(d.Warnings, "raw packet sockets observed (AF_PACKET): the service sees network traffic; keep this tool's config reviewed.")
	}
	d.Directives = append(d.Directives, Directive{"RestrictAddressFamilies", strings.Join(allowed, " ")})
	if fams["AF_INET"] || fams["AF_INET6"] {
		d.Notes = append(d.Notes, "network families restricted to those observed, plus local AF_UNIX.")
	} else if opts.AllowLateNetwork {
		d.Notes = append(d.Notes, "no sockets observed, but --allow-late-network keeps IPv4/IPv6 available.")
	} else {
		d.Notes = append(d.Notes, "no network use observed: only local AF_UNIX sockets are allowed.")
	}

	// Kernel and namespace protections, skipped when observed behavior needs them.
	d.Directives = append(d.Directives,
		Directive{"ProtectKernelTunables", "true"},
		Directive{"ProtectKernelModules", "true"},
		Directive{"ProtectKernelLogs", "true"},
		Directive{"ProtectClock", "true"},
		Directive{"ProtectControlGroups", "true"},
		Directive{"LockPersonality", "true"},
		Directive{"RestrictRealtime", "true"},
	)
	if opts.RemoveIPC {
		d.Directives = append(d.Directives, Directive{"RemoveIPC", "true"})
	} else {
		d.Notes = append(d.Notes, "SysV/POSIX IPC left in place: IPC calls are not in the traced syscall classes, so removal is opt-in (--remove-ipc).")
	}
	if o.UsesMount {
		d.Warnings = append(d.Warnings, "mount calls observed: RestrictNamespaces left off and capabilities may be required. Sandbox value is limited for this service.")
	} else {
		d.Directives = append(d.Directives, Directive{"RestrictNamespaces", "true"})
	}
	if o.UsesPtrace {
		d.Warnings = append(d.Warnings, "ptrace observed: this looks like a debugger/tracer. A sandboxed configuration cannot restrict its target processes.")
	}
	if opts.PrivateDevices {
		d.Directives = append(d.Directives, Directive{"PrivateDevices", "true"})
	}
	return d
}

func hasPrefixIn(paths []string, prefix string) bool {
	for _, p := range paths {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

func partitionWrites(writes []string) (broad, normal, home []string) {
	for _, w := range writes {
		switch {
		case hasPrefix(w, dangerousWritePrefixes):
			broad = append(broad, w)
		case hasPrefix(w, homePrefixes):
			home = append(home, w)
			normal = append(normal, w)
		default:
			normal = append(normal, w)
		}
	}
	return broad, normal, home
}

// Render writes the Decision as a systemd drop-in override file.
func Render(d Decision) string {
	var b strings.Builder
	b.WriteString("# Generated by unitguard. Review warnings before applying.\n[Service]\n")
	for _, dir := range d.Directives {
		if dir.Value == "" {
			fmt.Fprintf(&b, "%s=\n", dir.Key)
		} else {
			fmt.Fprintf(&b, "%s=%s\n", dir.Key, dir.Value)
		}
	}
	return b.String()
}
