package parser

import (
	"encoding/xml"
	"fmt"
	"strings"

	"threatdoc-cli/internal/finding"
)

func init() {
	Register("nessus", &NessusParser{})
}

type NessusParser struct{}

type nessusReport struct {
	Hosts []nessusReportHost `xml:"Report>ReportHost"`
}

type nessusReportHost struct {
	Name  string             `xml:"name,attr"`
	Items []nessusReportItem `xml:"ReportItem"`
}

type nessusReportItem struct {
	Port          string   `xml:"port,attr"`
	SvcName       string   `xml:"svc_name,attr"`
	Protocol      string   `xml:"protocol,attr"`
	Severity      string   `xml:"severity,attr"`
	PluginID      string   `xml:"pluginID,attr"`
	PluginName    string   `xml:"pluginName,attr"`
	Synopsis      string   `xml:"synopsis"`
	Description   string   `xml:"description"`
	Solution      string   `xml:"solution"`
	RiskFactor    string   `xml:"risk_factor"`
	CvssBaseScore string   `xml:"cvss_base_score"`
	CVE           []string `xml:"cve"`
}

var nessusSeverity = map[string]string{
	"0": "Informational",
	"1": "Low",
	"2": "Medium",
	"3": "High",
	"4": "Critical",
}

func (p *NessusParser) Parse(data []byte) ([]finding.Finding, error) {
	var report nessusReport
	if err := xml.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parsing nessus XML: %w", err)
	}

	var findings []finding.Finding
	for _, host := range report.Hosts {
		for _, item := range host.Items {
			findings = append(findings, toNessusFinding(host, item))
		}
	}
	return findings, nil
}

func toNessusFinding(host nessusReportHost, item nessusReportItem) finding.Finding {
	severity, ok := nessusSeverity[strings.TrimSpace(item.Severity)]
	if !ok {
		severity = "Informational"
	}

	var desc strings.Builder
	if item.Synopsis != "" {
		desc.WriteString(strings.TrimSpace(item.Synopsis))
	}
	if item.Description != "" {
		if desc.Len() > 0 {
			desc.WriteString("\n\n")
		}
		desc.WriteString(strings.TrimSpace(item.Description))
	}

	target := host.Name
	if item.Port != "" && item.Port != "0" {
		target = fmt.Sprintf("%s:%s", target, item.Port)
		if item.SvcName != "" {
			target += " (" + item.SvcName + ")"
		}
	}
	if target != "" {
		fmt.Fprintf(&desc, "\n\nHost: %s", target)
	}
	if item.CvssBaseScore != "" {
		fmt.Fprintf(&desc, "\nCVSS base score: %s", item.CvssBaseScore)
	}
	if len(item.CVE) > 0 {
		fmt.Fprintf(&desc, "\nCVE: %s", strings.Join(item.CVE, ", "))
	}
	if item.Solution != "" && !strings.EqualFold(strings.TrimSpace(item.Solution), "n/a") {
		fmt.Fprintf(&desc, "\n\nSolution: %s", strings.TrimSpace(item.Solution))
	}

	externalID := fmt.Sprintf("%s:%s:%s", host.Name, item.Port, item.PluginID)

	return finding.Finding{
		Title:       item.PluginName,
		Severity:    severity,
		Description: strings.TrimSpace(desc.String()),
		ExternalID:  externalID,
	}
}
