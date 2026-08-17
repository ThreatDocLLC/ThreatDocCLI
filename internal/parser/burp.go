package parser

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"

	"threatdoc-cli/internal/finding"
)

func init() {
	Register("burp", &BurpParser{})
}

type BurpParser struct{}

type burpReport struct {
	Issues []burpIssue `xml:"issue"`
}

type burpHost struct {
	IP    string `xml:"ip,attr"`
	Value string `xml:",chardata"`
}

type burpMessage struct {
	Base64 string `xml:"base64,attr"`
	Value  string `xml:",chardata"`
}

type burpRequestResponse struct {
	Request  burpMessage `xml:"request"`
	Response burpMessage `xml:"response"`
}

type burpIssue struct {
	SerialNumber string   `xml:"serialNumber"`
	Type         string   `xml:"type"`
	Name         string   `xml:"name"`
	Host         burpHost `xml:"host"`
	Path         string   `xml:"path"`
	Location     string   `xml:"location"`
	Severity     string   `xml:"severity"`
	Confidence   string   `xml:"confidence"`

	IssueBackground string `xml:"issueBackground"`
	IssueDetail     string `xml:"issueDetail"`

	RequestResponse []burpRequestResponse `xml:"requestresponse"`
}

var burpSeverity = map[string]string{
	"high":        "High",
	"medium":      "Medium",
	"low":         "Low",
	"information": "Informational",
}

var htmlTag = regexp.MustCompile(`<[^>]+>`)

func stripHTML(s string) string {
	return strings.TrimSpace(htmlTag.ReplaceAllString(s, ""))
}

func (p *BurpParser) Parse(data []byte) ([]finding.Finding, error) {
	var report burpReport
	if err := xml.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parsing burp XML: %w", err)
	}

	findings := make([]finding.Finding, 0, len(report.Issues))
	for _, issue := range report.Issues {

		if strings.EqualFold(strings.TrimSpace(issue.Severity), "false positive") {
			continue
		}
		findings = append(findings, toBurpFinding(issue))
	}
	return findings, nil
}

func toBurpFinding(issue burpIssue) finding.Finding {
	severity, ok := burpSeverity[strings.ToLower(strings.TrimSpace(issue.Severity))]
	if !ok {
		severity = "Informational"
	}

	detail := stripHTML(issue.IssueDetail)
	if detail == "" {
		detail = stripHTML(issue.IssueBackground)
	}

	var desc strings.Builder
	desc.WriteString(detail)

	target := strings.TrimSpace(issue.Host.Value) + strings.TrimSpace(issue.Path)
	if target != "" {
		fmt.Fprintf(&desc, "\n\nLocation: %s", target)
	}
	if loc := strings.TrimSpace(issue.Location); loc != "" && loc != strings.TrimSpace(issue.Path) {
		fmt.Fprintf(&desc, "\nEntry point: %s", loc)
	}
	if issue.Confidence != "" {
		fmt.Fprintf(&desc, "\nConfidence: %s", issue.Confidence)
	}
	if issue.SerialNumber != "" {
		fmt.Fprintf(&desc, "\nBurp serial number: %s", issue.SerialNumber)
	}

	return finding.Finding{
		Title:       issue.Name,
		Severity:    severity,
		Description: strings.TrimSpace(desc.String()),
		ExternalID:  strings.TrimSpace(issue.SerialNumber),
	}
}
