// Package trace summarizes strace output into a behavior profile used to
// synthesize least-privilege systemd sandboxing directives.
package trace

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Observation is the behavioral summary of one traced run. It is the JSON
// contract between `unitguard observe` and `unitguard generate`.
type Observation struct {
	// Writes holds absolute paths the process opened for writing or created.
	Writes []string `json:"writes"`
	// Families holds network address families observed, e.g. "AF_INET".
	Families []string `json:"families"`
	// Execs holds absolute paths of binaries the process executed.
	Execs []string `json:"execs"`
	// UsesPtrace is true when any ptrace call was observed.
	UsesPtrace bool `json:"uses_ptrace"`
	// UsesMount is true when any mount/umount call was observed.
	UsesMount bool `json:"uses_mount"`
}

var (
	// Matches lines like: openat(AT_FDCWD, "/var/lib/x", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3
	openRe = regexp.MustCompile(`\bopenat?\([^,]*,\s*"((?:[^"\\]|\\.)*)"[^)]*\)`)
	// Matches: connect(5, {sa_family=AF_INET, ... and socket(AF_INET6, ...
	familyRe = regexp.MustCompile(`\b(?:socket|connect)\([^\n]*?\b(AF_\w+)\b`)
	// Matches: execve("/usr/bin/foo", ...
	execRe = regexp.MustCompile(`\bexecve\("((?:[^"\\]|\\.)*)"`)
	// First quoted path in any line (for mkdir/unlink/rename-style calls).
	firstPathRe = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
)

func unquote(s string) string {
	return strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(s)
}

func isWriteCall(line string) bool {
	if strings.Contains(line, "O_WRONLY") || strings.Contains(line, "O_RDWR") ||
		strings.Contains(line, "O_CREAT") {
		return true
	}
	for _, call := range []string{"mkdir(", "mkdirat(", "unlink(", "unlinkat(", "rename(", "renameat(", "symlink(", "symlinkat(", "link(", "linkat(", "truncate(", "chmod(", "fchmodat(", "chown(", "fchownat(", "utimensat(", "mknodat(", "mknod("} {
		if strings.Contains(line, call) {
			return true
		}
	}
	return false
}

// Parse reads strace -f output and returns the observed behavior summary.
// Unknown lines are skipped; parsing never fails on unexpected content.
func Parse(r io.Reader) Observation {
	set := map[string]map[string]bool{"w": {}, "f": {}, "e": {}}
	var obs Observation
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		// Skip unfinished fragments; the resumed line carries the call again.
		if strings.Contains(line, "<unfinished ...>") {
			continue
		}
		if isWriteCall(line) {
			m := openRe.FindStringSubmatch(line)
			if m == nil {
				m = firstPathRe.FindStringSubmatch(line)
			}
			if m != nil {
				p := unquote(m[1])
				if strings.HasPrefix(p, "/") {
					set["w"][p] = true
				}
			}
		}
		if m := familyRe.FindStringSubmatch(line); m != nil {
			set["f"][m[1]] = true
		}
		if m := execRe.FindStringSubmatch(line); m != nil {
			set["e"][unquote(m[1])] = true
		}
		if strings.Contains(line, "ptrace(") {
			obs.UsesPtrace = true
		}
		if strings.Contains(line, "mount(") || strings.Contains(line, "umount2(") {
			obs.UsesMount = true
		}
	}
	obs.Writes = sortedKeys(set["w"])
	obs.Families = sortedKeys(set["f"])
	obs.Execs = sortedKeys(set["e"])
	return obs
}

// WritePrefixes collapses observed write paths into the minimal set of
// directory prefixes that cover them all.
func WritePrefixes(o Observation) []string {
	set := map[string]bool{}
	for _, p := range o.Writes {
		p = canonicalPath(p)
		dir := p
		if i := strings.LastIndex(dir, "/"); i > 0 {
			dir = dir[:i]
		} else {
			dir = "/"
		}
		set[dir] = true
	}
	dirs := sortedKeys(set)
	out := dirs[:0]
	for _, d := range dirs {
		covered := false
		for _, kept := range out {
			if strings.HasPrefix(d, kept+"/") || d == kept {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, d)
		}
	}
	return out
}

// canonicalPath normalizes well-known symlinked locations so generated
// paths match what systemd sees at runtime (/var/run is a symlink to /run).
func canonicalPath(p string) string {
	if p == "/var/run" {
		return "/run"
	}
	if strings.HasPrefix(p, "/var/run/") {
		return "/run/" + strings.TrimPrefix(p, "/var/run/")
	}
	return p
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func (o Observation) String() string {
	return fmt.Sprintf("writes=%d families=%v execs=%d ptrace=%v mount=%v",
		len(o.Writes), o.Families, len(o.Execs), o.UsesPtrace, o.UsesMount)

}
