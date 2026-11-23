package main

import (
	"fmt"
	"strings"
)

// splitWords splits a command line into arguments the way a minimal shell
// would: whitespace separates words, single quotes are literal, double
// quotes allow \" \\ \$ and \` escapes, and a backslash escapes the next
// byte outside quotes. It exists so flags like --cmd "sh -c 'echo hi'"
// keep their quoted structure instead of being chopped on spaces.
func splitWords(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	var quote rune // 0, '\'' or '"'
	escaped := false

	flush := func() {
		if inWord {
			words = append(words, cur.String())
			cur.Reset()
			inWord = false
		}
	}

	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && quote != '\'':
			escaped = true
			inWord = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
			inWord = true
		case r == '\'' || r == '"':
			quote = r
			inWord = true
		case r == ' ' || r == '\t' || r == '\n':
			flush()
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if escaped {
		cur.WriteRune('\\')
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated %c quote in command line", quote)
	}
	flush()
	return words, nil
}
