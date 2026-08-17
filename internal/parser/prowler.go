package parser

import (
	"encoding/json"
	"fmt"
	"strings"

	"threatdoc-cli/internal/finding"
)

func init() {
	Register("prowler", &ProwlerParser{})
}

type ProwlerParser struct{}

type prowlerFinding struct {
	FindingUniqueID string             `json:"FindingUniqueId"`
	CheckID         string             `json:"CheckID"`
	CheckTitle      string             `json:"CheckTitle"`
	Status          string             `json:"Status"`
	StatusExtended  string             `json:"StatusExtended"`
	Severity        string             `json:"Severity"`
	Description     string             `json:"Description"`
	Risk            string             `json:"Risk"`
	ResourceID      string             `json:"ResourceId"`
	ResourceType    string             `json:"ResourceType"`
	Region          string             `json:"Region"`
	AccountID       string             `json:"AccountId"`
	Remediation     prowlerRemediation `json:"Remediation"`
}

type prowlerRemediation struct {
	Recommendation prowlerRecommendation `json:"Recommendation"`
}

type prowlerRecommendation struct {
	Text string `json:"Text"`
	URL  string `json:"Url"`
}

var prowlerSeverity = map[string]string{
	"informational": "Informational",
	"info":          "Informational",
	"low":           "Low",
	"medium":        "Medium",
	"high":          "High",
	"critical":      "Critical",
}

func (p *ProwlerParser) Parse(data []byte) ([]finding.Finding, error) {
	var results []prowlerFinding
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("parsing prowler JSON: %w", err)
	}

	findings := make([]finding.Finding, 0, len(results))
	for _, r := range results {
		if !strings.EqualFold(strings.TrimSpace(r.Status), "FAIL") {
			continue
		}
		findings = append(findings, toProwlerFinding(r))
	}
	return findings, nil
}

func toProwlerFinding(r prowlerFinding) finding.Finding {
	severity, ok := prowlerSeverity[strings.ToLower(strings.TrimSpace(r.Severity))]
	if !ok {
		severity = "Informational"
	}

	title := r.CheckTitle
	if title == "" {
		title = r.CheckID
	}

	var desc strings.Builder
	if r.StatusExtended != "" {
		desc.WriteString(strings.TrimSpace(r.StatusExtended))
	} else if r.Description != "" {
		desc.WriteString(strings.TrimSpace(r.Description))
	}

	if r.Risk != "" {
		fmt.Fprintf(&desc, "\n\nRisk: %s", strings.TrimSpace(r.Risk))
	}

	resource := r.ResourceID
	if r.ResourceType != "" {
		resource = fmt.Sprintf("%s (%s)", resource, r.ResourceType)
	}
	if resource != "" {
		fmt.Fprintf(&desc, "\n\nResource: %s", resource)
	}
	if r.Region != "" {
		fmt.Fprintf(&desc, "\nRegion: %s", r.Region)
	}
	if r.AccountID != "" {
		fmt.Fprintf(&desc, "\nAccount: %s", r.AccountID)
	}
	if rec := strings.TrimSpace(r.Remediation.Recommendation.Text); rec != "" {
		fmt.Fprintf(&desc, "\n\nRemediation: %s", rec)
	}

	externalID := r.FindingUniqueID
	if externalID == "" {
		externalID = fmt.Sprintf("%s:%s:%s", r.CheckID, r.Region, r.ResourceID)
	}

	return finding.Finding{
		Title:       title,
		Severity:    severity,
		Description: strings.TrimSpace(desc.String()),
		ExternalID:  externalID,
	}
}
