package unit

import (
	"strings"
	"testing"
)

func TestSimpleExecStart(t *testing.T) {
	text := `[Unit]
Description=Demo

[Service]
Type=simple
ExecStart=/usr/bin/demo --port 8080 --data /var/lib/demo
Restart=always
`
	cmds, err := ParseExecStart(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("got %d commands", len(cmds))
	}
	want := []string{"/usr/bin/demo", "--port", "8080", "--data", "/var/lib/demo"}
	if strings.Join(cmds[0].Argv, " ") != strings.Join(want, " ") {
		t.Errorf("argv = %v", cmds[0].Argv)
	}
}

func TestPrefixModifiersAndQuotes(t *testing.T) {
	text := `[Service]
ExecStart=-/usr/bin/demo --name "my service" --path '/var/lib/my service'
`
	cmds, err := ParseExecStart(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if !cmds[0].Optional {
		t.Error("optional flag not detected")
	}
	if cmds[0].Argv[2] != "my service" || cmds[0].Argv[4] != "/var/lib/my service" {
		t.Errorf("quoting broken: %v", cmds[0].Argv)
	}
}

func TestIgnoresPrePostAndOtherSections(t *testing.T) {
	text := `[Service]
ExecStartPre=/usr/bin/prep
ExecStart=/usr/bin/main
ExecStartPost=/usr/bin/cleanup

[Install]
WantedBy=multi-user.target
`
	cmds, _ := ParseExecStart(strings.NewReader(text))
	if len(cmds) != 1 || cmds[0].Argv[0] != "/usr/bin/main" {
		t.Errorf("cmds = %v", cmds)
	}
}

func TestResetThenSet(t *testing.T) {
	text := `[Service]
ExecStart=
ExecStart=/usr/bin/real
`
	cmds, _ := ParseExecStart(strings.NewReader(text))
	if len(cmds) != 1 || cmds[0].Argv[0] != "/usr/bin/real" {
		t.Errorf("reset handling broken: %v", cmds)
	}
}

func TestSpecifiersReported(t *testing.T) {
	text := `[Service]
ExecStart=/usr/bin/demo --home %h --id %i
`
	cmds, _ := ParseExecStart(strings.NewReader(text))
	got := strings.Join(cmds[0].UnexpandedSpecifiers, ",")
	if got != "%h,%i" {
		t.Errorf("specifiers = %q", got)
	}
}

func TestLineContinuation(t *testing.T) {
	text := "[Service]\nExecStart=/usr/bin/demo \\\n  --flag value\n"
	cmds, _ := ParseExecStart(strings.NewReader(text))
	if len(cmds) != 1 || len(cmds[0].Argv) != 3 {
		t.Errorf("continuation broken: %v", cmds)
	}
}
