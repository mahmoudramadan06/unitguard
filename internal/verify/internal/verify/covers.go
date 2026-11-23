package verify

import (
	"fmt"
	"strings"

	"github.com/mahmoudramadan06/unitguard/internal/trace"
)

// Covers checks that a generated policy still permits everything the trace
// observed. rwPaths is the generated ReadWritePaths list; families is the
// generated RestrictAddressFamilies list, or nil when unrestricted;
// downgrade is true when the generator deliberately fell back to
// ProtectSystem=full because an observed write root was too broad (the gap
// is already surfaced to the user as a warning, so write coverage is not
// checkable then). It returns one human-readable violation per problem,
// nil when sound.
var apiPseudoDevices = []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty"}

func isAPIPseudoDevice(path string) bool {
	for _, d := range apiPseudoDevices {
		if path == d {
			return true
		}
	}
	return false
}

func Covers(obs trace.Observation, rwPaths []string, families []string, downgrade bool) []string {
	var violations []string

	// A root entry is invalid input regardless of downgrade: it says nothing
	// about which subtrees the service may write.
	for _, prefix := range rwPaths {
		if prefix == "/" {
			violations = append(violations, `ReadWritePaths entry "/" is too broad to be meaningful`)
		}
	}

	if !downgrade {
		for _, path := range obs.Writes {
			// API pseudo-devices stay available writable under ProtectSystem
			// (man systemd.exec), so they need no ReadWritePaths coverage.
			if isAPIPseudoDevice(path) {
				continue
			}
			covered := false
			for _, prefix := range rwPaths {
				if path == prefix || strings.HasPrefix(path, prefix+"/") {
					covered = true
					break
				}
			}
			if !covered {
				violations = append(violations, fmt.Sprintf(
					"observed write %q is not covered by ReadWritePaths %v", path, rwPaths))
			}
		}
	}

	if families != nil {
		allowed := make(map[string]bool, len(families))
		for _, family := range families {
			allowed[family] = true
		}

		// Report each missing family once, even when AF_UNIX is both observed
		// and required as the mandatory local-IPC floor.
		required := make([]string, 0, len(obs.Families)+1)
		seen := make(map[string]bool, len(obs.Families)+1)
		for _, family := range obs.Families {
			if !seen[family] {
				seen[family] = true
				required = append(required, family)
			}
		}
		if !seen["AF_UNIX"] {
			required = append(required, "AF_UNIX")
		}
		for _, family := range required {
			if !allowed[family] {
				violations = append(violations, fmt.Sprintf(
					"address family %q is missing from RestrictAddressFamilies", family))
			}
		}
	}

	return violations
}
