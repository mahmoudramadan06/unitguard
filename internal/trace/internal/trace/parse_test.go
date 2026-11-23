package trace

import (
	"strings"
	"testing"
)

const sampleTrace = `
12345 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
12345 openat(AT_FDCWD, "/var/lib/app/data.db", O_RDWR|O_CREAT, 0644) = 3
12345 openat(AT_FDCWD, "/var/lib/app/wal.log", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4
12346 openat(AT_FDCWD, "/home/sandbox/notes.txt", O_WRONLY) = 3
12345 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
12345 connect(3, {sa_family=AF_INET, sin_port=htons(443)}, 16) = 0
12345 socket(AF_UNIX, SOCK_STREAM, 0) = 4
12345 execve("/usr/bin/helper", ["helper", "--fast"], 0x7fff) = 0
12345 openat(AT_FDCWD, "/proc/meminfo", O_RDONLY <unfinished ...>
12345 mkdir("/var/lib/app/tmp", 0755) = 0
`

func TestParseCollectsBehavior(t *testing.T) {
	obs := Parse(strings.NewReader(sampleTrace))

	assertHas := func(list []string, want string) {
		t.Helper()
		for _, got := range list {
			if got == want {
				return
			}
		}
		t.Errorf("missing %q in %v", want, list)
	}

	assertHas(obs.Writes, "/var/lib/app/data.db")
	assertHas(obs.Writes, "/var/lib/app/wal.log")
	assertHas(obs.Writes, "/var/lib/app/tmp")
	assertHas(obs.Writes, "/home/sandbox/notes.txt")
	assertHas(obs.Families, "AF_INET")
	assertHas(obs.Families, "AF_UNIX")
	assertHas(obs.Execs, "/usr/bin/helper")

	for _, w := range obs.Writes {
		if w == "/etc/ld.so.cache" || w == "/proc/meminfo" {
			t.Errorf("read-only open %q counted as write", w)
		}
	}
}

func TestParseFlags(t *testing.T) {
	obs := Parse(strings.NewReader(`1 ptrace(PTRACE_TRACEME, 0, 0, 0) = 0
2 mount("tmpfs", "/mnt", "tmpfs", 0, "") = 0
`))
	if !obs.UsesPtrace || !obs.UsesMount {
		t.Errorf("flags not set: %+v", obs)
	}
}

func TestWritePrefixesCollapses(t *testing.T) {
	obs := Observation{Writes: []string{
		"/var/lib/app/a.db", "/var/lib/app/b.db", "/var/log/app/x.log",
	}}
	got := WritePrefixes(obs)
	if len(got) != 2 || got[0] != "/var/lib/app" || got[1] != "/var/log/app" {
		t.Errorf("prefixes = %v", got)
	}
}

func TestParseIgnoresGarbage(t *testing.T) {
	obs := Parse(strings.NewReader("not a trace line\n+++ exited with 0 +++\n"))
	if len(obs.Writes) != 0 || len(obs.Families) != 0 {
		t.Errorf("garbage parsed into behavior: %+v", obs)
	}
}

func TestWritePrefixesCanonicalizesVarRun(t *testing.T) {
	o := Observation{Writes: []string{"/var/lib/app/x.db", "/var/run/app.pid"}}
	got := WritePrefixes(o)
	for _, p := range got {
		if strings.HasPrefix(p, "/var/run") {
			t.Errorf("/var/run not canonicalized: %v", got)
		}
	}
	found := false
	for _, p := range got {
		if p == "/run" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected /run in %v", got)
	}
}
