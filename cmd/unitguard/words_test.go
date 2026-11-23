package main

import (
	"reflect"
	"testing"
)

func TestSplitWords(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"ls -l /tmp", []string{"ls", "-l", "/tmp"}},
		{`sh -c 'echo hi > /tmp/x'`, []string{"sh", "-c", "echo hi > /tmp/x"}},
		{`curl -fs "http://localhost:8080/health check"`, []string{"curl", "-fs", "http://localhost:8080/health check"}},
		{`echo "a \"quoted\" word"`, []string{"echo", `a "quoted" word`}},
		{`echo a\ b`, []string{"echo", "a b"}},
		{"  spaced   out  ", []string{"spaced", "out"}},
		{"one", []string{"one"}},
		{"", nil},
		{"''", []string{""}},
	}
	for _, c := range cases {
		got, err := splitWords(c.in)
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: got %#v, want %#v", c.in, got, c.want)
		}
	}
}

func TestSplitWordsUnterminatedQuote(t *testing.T) {
	if _, err := splitWords(`sh -c 'oops`); err == nil {
		t.Fatal("expected error for unterminated quote")
	}
}
