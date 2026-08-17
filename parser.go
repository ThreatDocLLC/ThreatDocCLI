// Package parser holds one adapter per supported scanner. Each adapter's
// only job is mapping that tool's own output format onto the normalized
// finding.Finding shape — nothing about the scanner leaks past this package.
package parser

import "threatdoc-cli/internal/finding"

type Parser interface {
	Parse(data []byte) ([]finding.Finding, error)
}

var registry = map[string]Parser{}

func Register(name string, p Parser) {
	registry[name] = p
}

func Get(name string) (Parser, bool) {
	p, ok := registry[name]
	return p, ok
}

func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
