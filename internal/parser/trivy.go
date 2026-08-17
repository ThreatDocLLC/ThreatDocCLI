package parser

import (
	"encoding/json"
	"fmt"
	"strings"

	"threatdoc-cli/internal/finding"
)

func init() {
	Register("trivy", &TrivyParser{})
}

type TrivyParser struct{}

type trivyReport struct {
	ArtifactName string        `json:"ArtifactName"`
	Results      []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string               `json:"Target"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
}

type trivyVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	Severity         string   `json:"Severity"`
	PrimaryURL       string   `json:"PrimaryURL"`
	References       []string `json:"References"`
}

var trivySeverity = map[string]string{
	"unknown":  "Informational",
	"low":      "Low",
	"medium":   "Medium",
	"high":     "High",
	"critical": "Critical",
}

func (p *TrivyParser) Parse(data []byte) ([]finding.Finding, error) {
	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parsing trivy JSON: %w", err)
	}

	var findings []finding.Finding
	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			findings = append(findings, toTrivyFinding(result, vuln))
		}
	}
	return findings, nil
}

func toTrivyFinding(result trivyResult, vuln trivyVulnerability) finding.Finding {
	severity, ok := trivySeverity[strings.ToLower(strings.TrimSpace(vuln.Severity))]
	if !ok {
		severity = "Informational"
	}

	title := vuln.Title
	if title == "" {
		title = vuln.VulnerabilityID
	}

	var desc strings.Builder
	desc.WriteString(strings.TrimSpace(vuln.Description))

	pkg := vuln.PkgName
	if vuln.InstalledVersion != "" {
		pkg = fmt.Sprintf("%s@%s", pkg, vuln.InstalledVersion)
	}
	if pkg != "" {
		fmt.Fprintf(&desc, "\n\nPackage: %s", pkg)
	}
	if vuln.FixedVersion != "" {
		fmt.Fprintf(&desc, "\nFixed in: %s", vuln.FixedVersion)
	}
	if result.Target != "" {
		fmt.Fprintf(&desc, "\nTarget: %s", result.Target)
	}

	var refs []string
	if vuln.PrimaryURL != "" {
		refs = append(refs, vuln.PrimaryURL)
	}
	refs = append(refs, vuln.References...)
	if len(refs) > 0 {
		fmt.Fprintf(&desc, "\n\nReferences:\n%s", strings.Join(refs, "\n"))
	}

	return finding.Finding{
		Title:       title,
		Severity:    severity,
		Description: strings.TrimSpace(desc.String()),
		ExternalID:  fmt.Sprintf("%s:%s:%s", result.Target, vuln.PkgName, vuln.VulnerabilityID),
	}
}
