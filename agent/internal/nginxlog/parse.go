package nginxlog

import (
	"strings"
	"time"
)

const DefaultService = "nginx"

const maxText = 8 << 10

var severities = [8]string{
	"emerg", "alert", "crit", "error", "warn", "notice", "info", "debug",
}

type Line struct {
	TS       time.Time `json:"ts"`
	Service  string    `json:"service"`
	Severity string    `json:"severity,omitempty"`
	Text     string    `json:"text"`
}

func Parse(raw []byte, at time.Time) (Line, bool) {
	line := Line{TS: at, Service: DefaultService}

	body := strings.TrimRight(string(raw), "\x00\r\n")
	if body == "" {
		return Line{}, false
	}

	rest := body

	if pri, tail, ok := priority(rest); ok {
		line.Severity = severities[pri%8]
		rest = tail
	}

	if service, tail, ok := head(rest); ok {
		line.Service = service
		rest = tail
	}

	if len(rest) > maxText {
		rest = rest[:maxText]
	}

	line.Text = rest

	return line, rest != ""
}

func priority(s string) (int, string, bool) {
	if len(s) < 3 || s[0] != '<' {
		return 0, s, false
	}

	end := strings.IndexByte(s, '>')
	if end < 2 || end > 4 {
		return 0, s, false
	}

	pri := 0

	for i := 1; i < end; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, s, false
		}
		pri = pri*10 + int(c-'0')
	}

	if pri > 191 {
		return 0, s, false
	}

	return pri, s[end+1:], true
}

func head(s string) (string, string, bool) {
	rest := s

	for i := 0; i < 3; i++ {
		_, tail, ok := field(rest)
		if !ok {
			return "", s, false
		}
		rest = tail
	}

	for i := 0; i < 2; i++ {
		tok, tail, ok := field(rest)
		if !ok {
			return "", s, false
		}

		rest = tail

		if name, cut := strings.CutSuffix(tok, ":"); cut && name != "" {
			return name, rest, true
		}
	}

	return "", s, false
}

func field(s string) (string, string, bool) {
	s = strings.TrimLeft(s, " ")
	if s == "" {
		return "", "", false
	}

	at := strings.IndexByte(s, ' ')
	if at < 0 {
		return s, "", true
	}

	return s[:at], strings.TrimLeft(s[at+1:], " "), true
}
