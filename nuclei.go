package parser

import (
	"encoding/json"
	"fmt"
	"strings"

	"threatdoc-cli/internal/finding"
)

func init() {
	Register("nuclei", &NucleiParser{})
}

type NucleiParser struct{}

type nucleiInfo struct {
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Reference   []string `json:"reference"`
}

type nucleiResult struct {
	TemplateID string     `json:"template-id"`
	Info       nucleiInfo `json:"info"`
	Host       string     `json:"host"`
	MatchedAt  string     `json:"matched-at"`
}

var nucleiSeverity = map[string]string{
	"critical": "Critical",
	"high":     "High",
	"medium":   "Medium",
	"low":      "Low",
	"info":     "Informational",
}

func (p *NucleiParser) Parse(data []byte) ([]finding.Finding, error) {
	results, err := decodeNucleiResults(data)
	if err != nil {
		return nil, err
	}

	findings := make([]finding.Finding, 0, len(results))
	for _, r := range results {
		findings = append(findings, toNucleiFinding(r))
	}
	return findings, nil
}

func decodeNucleiResults(data []byte) ([]nucleiResult, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}

	if strings.HasPrefix(trimmed, "[") {
		var results []nucleiResult
		if err := json.Unmarshal(data, &results); err != nil {
			return nil, fmt.Errorf("parsing nuclei JSON array: %w", err)
		}
		return results, nil
	}

	var results []nucleiResult
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r nucleiResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("parsing nuclei JSONL line: %w", err)
		}
		results = append(results, r)
	}
	return results, nil
}

func toNucleiFinding(r nucleiResult) finding.Finding {
	severity, ok := nucleiSeverity[strings.ToLower(r.Info.Severity)]
	if !ok {
		severity = "Informational"
	}

	title := r.Info.Name
	if title == "" {
		title = r.TemplateID
	}

	target := r.MatchedAt
	if target == "" {
		target = r.Host
	}

	var desc strings.Builder
	desc.WriteString(r.Info.Description)
	if target != "" {
		fmt.Fprintf(&desc, "\n\nMatched at: %s", target)
	}
	if len(r.Info.Reference) > 0 {
		fmt.Fprintf(&desc, "\n\nReferences:\n%s", strings.Join(r.Info.Reference, "\n"))
	}

	return finding.Finding{
		Title:       title,
		Severity:    severity,
		Description: strings.TrimSpace(desc.String()),
	}
}
