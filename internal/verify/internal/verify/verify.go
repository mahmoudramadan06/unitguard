// Package verify validates generated drop-ins with systemd's own tooling.
package verify

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Analyzer runs systemd-analyze; replaceable in tests.
type Analyzer struct {
	Bin string // defaults to "systemd-analyze"
}

func (a Analyzer) bin() string {
	if a.Bin != "" {
		return a.Bin
	}
	return "systemd-analyze"
}

// Lint runs `systemd-analyze verify` on the given unit file path and
// returns its diagnostics. An empty report means systemd accepted the file.
func (a Analyzer) Lint(ctx context.Context, path string) (string, error) {
	cmd := exec.CommandContext(ctx, a.bin(), "verify", path)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

var scoreRe = regexp.MustCompile(`(?m)^\s*([0-9]+\.[0-9])\s+(\S+)\s*$`)

// SecurityScore runs `systemd-analyze security <unit>` and parses the
// overall exposure level. Works offline for unit file paths.
func (a Analyzer) SecurityScore(ctx context.Context, unitOrPath string) (float64, string, error) {
	cmd := exec.CommandContext(ctx, a.bin(), "security", unitOrPath)
	out, err := cmd.CombinedOutput()
	text := string(out)
	if err != nil {
		return 0, text, fmt.Errorf("systemd-analyze security: %w", err)
	}
	// The final line looks like: "-> Overall exposure level for x: 9.2 UNSAFE 😐"
	lines := strings.Split(text, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(lines[i], "Overall exposure level") {
			if m := scoreRe.FindStringSubmatch(lines[i]); m != nil {
				v, perr := strconv.ParseFloat(m[1], 64)
				return v, text, perr
			}
		}
	}
	return 0, text, fmt.Errorf("could not parse overall exposure level")
}
