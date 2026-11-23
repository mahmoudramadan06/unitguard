// Package unit extracts what unitguard needs from systemd unit files.
package unit

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// ExecStart holds one parsed ExecStart command from a unit's [Service] section.
type ExecStart struct {
	// Argv is the command split into arguments, prefix modifiers stripped.
	Argv []string
	// Raw is the original directive value, kept for diagnostics.
	Raw string
	// Optional is true when the command carries the "-" prefix (failures ignored).
	Optional bool
	// UnexpandedSpecifiers lists % specifiers left in the command; callers
	// should surface them because tracing a template command may mislead.
	UnexpandedSpecifiers []string
}

var sectionRe = func(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if len(line) >= 2 && line[0] == '[' && line[len(line)-1] == ']' {
		return line[1 : len(line)-1], true
	}
	return "", false
}

// ParseExecStart reads a unit file (or `systemctl cat` output) and returns
// every ExecStart command in its [Service] section. ExecStartPre/Post and
// non-Service sections are ignored. An empty ExecStart= reset is honored.
func ParseExecStart(r io.Reader) ([]ExecStart, error) {
	var out []ExecStart
	inService := false
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	var logical strings.Builder
	haveLogical := false

	flush := func() {
		if !haveLogical {
			return
		}
		line := logical.String()
		logical.Reset()
		haveLogical = false
		if !inService || !strings.HasPrefix(line, "ExecStart=") {
			return
		}
		val := strings.TrimPrefix(line, "ExecStart=")
		if strings.TrimSpace(val) == "" {
			out = nil // explicit reset
			return
		}
		out = append(out, parseCommand(val))
	}

	scanned := false
	for sc.Scan() {
		scanned = true
		line := sc.Text()
		trimmed := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmed, "\\") && !strings.HasSuffix(trimmed, "\\\\") {
			logical.WriteString(strings.TrimSuffix(trimmed, "\\"))
			haveLogical = true
			continue
		}
		logical.WriteString(trimmed)
		haveLogical = true
		full := logical.String()
		if name, ok := sectionRe(full); ok {
			logical.Reset()
			haveLogical = false
			inService = strings.EqualFold(name, "Service")
			continue
		}
		flush()
	}
	flush()
	if !scanned {
		return nil, fmt.Errorf("empty unit content")
	}
	return out, sc.Err()
}

// parseCommand strips systemd prefix modifiers and splits a command line.
func parseCommand(val string) ExecStart {
	e := ExecStart{Raw: val}
	rest := strings.TrimLeft(val, " \t")
	for len(rest) > 0 {
		switch rest[0] {
		case '@', '-', ':', '+', '!':
			if rest[0] == '-' {
				e.Optional = true
			}
			rest = strings.TrimLeft(rest[1:], " \t")
			if len(rest) > 0 && rest[0] == '!' { // "!!" is one modifier
				rest = strings.TrimLeft(rest[1:], " \t")
			}
		default:
			goto modifiersDone
		}
	}
modifiersDone:
	argv, specs := splitFields(rest)
	e.Argv = argv
	e.UnexpandedSpecifiers = specs
	return e
}

// splitFields splits on unquoted whitespace, honoring single and double
// quotes, and reports any % specifiers found in the arguments.
func splitFields(s string) ([]string, []string) {
	var out []string
	specSeen := map[string]bool{}
	var specs []string
	var cur strings.Builder
	inField := false
	var quote byte
	flush := func() {
		if inField {
			out = append(out, cur.String())
			cur.Reset()
			inField = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			quote = c
			inField = true
		case c == ' ' || c == '\t':
			flush()
		case c == '%' && i+1 < len(s):
			spec := "%" + string(s[i+1])
			if s[i+1] == '%' {
				cur.WriteByte('%')
				i++
			} else {
				if !specSeen[spec] {
					specSeen[spec] = true
					specs = append(specs, spec)
				}
				cur.WriteString(spec)
				i++
			}
		default:
			cur.WriteByte(c)
			inField = true
		}
	}
	flush()
	return out, specs
}
