package cmd

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"threatdoc-cli/internal/client"
	"threatdoc-cli/internal/finding"
	"threatdoc-cli/internal/parser"
	"threatdoc-cli/internal/state"
)

var severityRank = map[string]int{
	"Informational": 0,
	"Low":           1,
	"Medium":        2,
	"High":          3,
	"Critical":      4,
}

func RunIngest(args []string) int {
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)
	tool := fs.String("tool", "", "scanner that produced the input (e.g. nuclei)")
	file := fs.String("file", "", "path to the tool's output file (reads stdin if omitted)")
	reportID := fs.String("report", os.Getenv("THREATDOC_REPORT_ID"), "report id (or THREATDOC_REPORT_ID)")
	token := fs.String("token", os.Getenv("THREATDOC_TOKEN"), "CLI token (or THREATDOC_TOKEN)")
	reportKey := fs.String("report-key", os.Getenv("THREATDOC_REPORT_KEY"), "report key, required only if the report has encryption enabled (or THREATDOC_REPORT_KEY)")
	baseURL := fs.String("url", envOr("THREATDOC_URL", "https://app.threatdoc.com"), "ThreatDoc base URL")
	minSeverity := fs.String("min-severity", "Medium", "minimum severity to ingest (Informational, Low, Medium, High, Critical)")
	dryRun := fs.Bool("dry-run", false, "print what would be created without uploading anything")
	noDedup := fs.Bool("no-dedup", false, "upload every result even if its tool-provided id was already ingested before")
	stateFile := fs.String("state-file", envOr("THREATDOC_STATE_FILE", state.DefaultPath()), "local file tracking already-ingested ids (or THREATDOC_STATE_FILE)")

	fs.Parse(args)

	if *tool == "" {
		fmt.Fprintln(os.Stderr, "error: --tool is required")
		return 1
	}
	p, ok := parser.Get(*tool)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: unknown tool %q (available: %s)\n", *tool, strings.Join(parser.Names(), ", "))
		return 1
	}

	if *reportID == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "error: --report and --token are required (or THREATDOC_REPORT_ID / THREATDOC_TOKEN)")
		return 1
	}

	st, err := state.Load(*stateFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading state file %s: %v\n", *stateFile, err)
		return 1
	}

	data, err := readInput(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %v\n", err)
		return 1
	}

	findings, err := p.Parse(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing %s output: %v\n", *tool, err)
		return 1
	}

	filtered := filterBySeverity(findings, *minSeverity)
	fmt.Printf("Parsed %d result(s), %d at or above %s severity\n", len(findings), len(filtered), *minSeverity)

	toUpload, alreadySeen := partitionSeen(filtered, *reportID, *tool, st, *noDedup)
	if alreadySeen > 0 {
		fmt.Printf("Skipping %d already ingested in a previous run (use --no-dedup to force)\n", alreadySeen)
	}

	if *dryRun {
		for _, f := range toUpload {
			fmt.Printf("  [%s] %s\n", f.Severity, f.Title)
		}
		fmt.Println("Dry run — nothing was uploaded.")
		return 0
	}

	return upload(client.New(*baseURL, *token, *reportKey), *reportID, *tool, toUpload, st)
}

func readInput(path string) ([]byte, error) {
	if path != "" {
		return os.ReadFile(path)
	}
	return io.ReadAll(os.Stdin)
}

func filterBySeverity(findings []finding.Finding, minSeverity string) []finding.Finding {
	threshold, ok := severityRank[normalizeSeverity(minSeverity)]
	if !ok {
		threshold = severityRank["Medium"]
	}

	filtered := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		if rank, ok := severityRank[f.Severity]; ok && rank >= threshold {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func partitionSeen(findings []finding.Finding, reportID, tool string, st *state.State, noDedup bool) (fresh []finding.Finding, skipped int) {
	if noDedup {
		return findings, 0
	}

	fresh = make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		if st.Seen(reportID, tool, f.ExternalID) {
			skipped++
			continue
		}
		fresh = append(fresh, f)
	}
	return fresh, skipped
}

func upload(c *client.Client, reportID, tool string, findings []finding.Finding, st *state.State) int {
	created := 0
	for _, f := range findings {
		result := c.CreateFinding(reportID, f)
		if result.RateLimited {
			fmt.Fprintf(os.Stderr, "rate limited after %d finding(s) — wait a few minutes and re-run with the remaining input\n", created)
			return 1
		}
		if result.Err != nil {
			fmt.Fprintf(os.Stderr, "  failed: %s — %v\n", f.Title, result.Err)
			continue
		}
		created++
		fmt.Printf("  created: [%s] %s\n", f.Severity, f.Title)

		if err := st.MarkSeen(reportID, tool, f.ExternalID); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: created but failed to record locally for dedup: %v\n", err)
		}
	}

	fmt.Printf("Done — %d/%d finding(s) created.\n", created, len(findings))
	return 0
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "informational", "info":
		return "Informational"
	case "low":
		return "Low"
	case "medium":
		return "Medium"
	case "high":
		return "High"
	case "critical":
		return "Critical"
	default:
		return "Medium"
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
