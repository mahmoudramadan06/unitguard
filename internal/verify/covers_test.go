package verify

import (
	"strings"
	"testing"

	"github.com/mahmoudramadan06/unitguard/internal/trace"
)

func TestCovers(t *testing.T) {
	tests := []struct {
		name      string
		obs       trace.Observation
		rwPaths   []string
		families  []string
		downgrade bool
		want      []string // substrings of the violations, in order
	}{
		{
			name:     "covered nested path",
			obs:      trace.Observation{Writes: []string{"/var/lib/app/data.db", "/run/app.pid"}},
			rwPaths:  []string{"/var/lib/app", "/run/app.pid"},
			families: []string{"AF_UNIX"},
		},
		{
			name:     "uncovered path reported",
			obs:      trace.Observation{Writes: []string{"/var/lib/app/data.db", "/etc/app.conf"}},
			rwPaths:  []string{"/var/lib/app"},
			families: []string{"AF_UNIX"},
			want:     []string{"/etc/app.conf"},
		},
		{
			name:      "downgrade skips write check but still checks families",
			obs:       trace.Observation{Writes: []string{"/etc/app.conf"}, Families: []string{"AF_INET"}},
			rwPaths:   nil,
			families:  []string{"AF_UNIX"},
			downgrade: true,
			want:      []string{"AF_INET"},
		},
		{
			name:     "missing AF_UNIX floor reported",
			obs:      trace.Observation{},
			rwPaths:  nil,
			families: []string{"AF_INET"},
			want:     []string{"AF_UNIX"},
		},
		{
			name:     "observed missing AF_UNIX reported once",
			obs:      trace.Observation{Families: []string{"AF_UNIX", "AF_INET"}},
			rwPaths:  nil,
			families: []string{"AF_INET"},
			want:     []string{"AF_UNIX"},
		},
		{
			name:    "nil families skips family check",
			obs:     trace.Observation{Families: []string{"AF_INET", "AF_UNIX"}},
			rwPaths: nil,
		},
		{
			name:     "root rwPaths entry reported",
			obs:      trace.Observation{},
			rwPaths:  []string{"/"},
			families: []string{"AF_UNIX"},
			want:     []string{"too broad"},
		},
		{
			name:     "each problem reported separately",
			obs:      trace.Observation{Writes: []string{"/etc/app.conf"}, Families: []string{"AF_INET"}},
			rwPaths:  []string{"/"},
			families: []string{"AF_INET"},
			want:     []string{"too broad", "/etc/app.conf", "AF_UNIX"},
		},
		{
			name:     "empty observation is sound",
			obs:      trace.Observation{},
			rwPaths:  nil,
			families: []string{"AF_UNIX"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Covers(tt.obs, tt.rwPaths, tt.families, tt.downgrade)
			if len(got) != len(tt.want) {
				t.Fatalf("violations = %q, want %d violation(s): %q", got, len(tt.want), tt.want)
			}
			for i, want := range tt.want {
				if !strings.Contains(got[i], want) {
					t.Errorf("violation %d = %q, want it to mention %q", i, got[i], want)
				}
			}
		})
	}
}
