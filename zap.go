package parser

import (
	"encoding/xml"
	"fmt"
	"strings"

	"threatdoc-cli/internal/finding"
)

func init() {
	Register("zap", &ZapParser{})
}

type ZapParser struct{}

type zapReport struct {
	Sites []zapSite `xml:"site"`
}

type zapSite struct {
	Name   string         `xml:"name,attr"`
	Host   string         `xml:"host,attr"`
	Alerts []zapAlertItem `xml:"alerts>alertitem"`
}

type zapInstance struct {
	URI    string `xml:"uri"`
	Method string `xml:"method"`
	Param  string `xml:"param"`
}

type zapAlertItem struct {
	PluginID   string        `xml:"pluginid"`
	Alert      string        `xml:"alert"`
	Name       string        `xml:"name"`
	RiskCode   string        `xml:"riskcode"`
	Confidence string        `xml:"confidence"`
	Desc       string        `xml:"desc"`
	Solution   string        `xml:"solution"`
	CweID      string        `xml:"cweid"`
	Instances  []zapInstance `xml:"instances>instance"`
}

var zapRiskCode = map[string]string{
	"0": "Informational",
	"1": "Low",
	"2": "Medium",
	"3": "High",
}

const zapConfidenceFalsePositive = "0"

func (p *ZapParser) Parse(data []byte) ([]finding.Finding, error) {
	var report zapReport
	if err := xml.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parsing zap XML: %w", err)
	}

	var findings []finding.Finding
	for _, site := range report.Sites {
		for _, alert := range site.Alerts {
			if strings.TrimSpace(alert.Confidence) == zapConfidenceFalsePositive {
				continue
			}
			findings = append(findings, toZapFinding(site, alert))
		}
	}
	return findings, nil
}

func toZapFinding(site zapSite, alert zapAlertItem) finding.Finding {
	severity, ok := zapRiskCode[strings.TrimSpace(alert.RiskCode)]
	if !ok {
		severity = "Informational"
	}

	title := alert.Alert
	if title == "" {
		title = alert.Name
	}

	var desc strings.Builder
	desc.WriteString(stripHTML(alert.Desc))

	if len(alert.Instances) > 0 {
		desc.WriteString("\n\nInstances:")
		for _, inst := range alert.Instances {
			line := "\n  " + inst.URI
			if inst.Method != "" {
				line += " [" + inst.Method + "]"
			}
			if inst.Param != "" {
				line += " param: " + inst.Param
			}
			desc.WriteString(line)
		}
	}

	if solution := stripHTML(alert.Solution); solution != "" {
		fmt.Fprintf(&desc, "\n\nSolution: %s", solution)
	}
	if alert.CweID != "" {
		fmt.Fprintf(&desc, "\nCWE-%s", alert.CweID)
	}

	externalID := alert.PluginID
	if len(alert.Instances) > 0 && alert.Instances[0].URI != "" {
		externalID = alert.PluginID + ":" + alert.Instances[0].URI
	}
	if site.Host != "" {
		externalID = site.Host + ":" + externalID
	}

	return finding.Finding{
		Title:       title,
		Severity:    severity,
		Description: strings.TrimSpace(desc.String()),
		ExternalID:  externalID,
	}
}
