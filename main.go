package main

import (
	"fmt"
	"os"

	"threatdoc-cli/cmd"

	_ "threatdoc-cli/internal/parser"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "ingest":
		os.Exit(cmd.RunIngest(os.Args[2:]))
	case "version", "--version":
		fmt.Println("threatdoc-cli " + version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`threatdoc-cli - ingest scanner output into a ThreatDoc report

Usage:
  threatdoc ingest --tool <name> --report <id> --token <token> [--file <path>] [flags]

Commands:
  ingest    Parse a scanner's output and create findings from it
  version   Print the CLI version

Ingest flags:
  --tool          scanner that produced the input (options: nuclei, burp, zap, nessus, prowler, trivy)
  --file          path to the output file (reads stdin if omitted)
  --report        report id (or THREATDOC_REPORT_ID env var)
  --token         CLI token from the report's CLI Connect tab (or THREATDOC_TOKEN)
  --url           ThreatDoc base URL (or THREATDOC_URL; defaults to the production app)
  --min-severity  minimum severity to ingest (default: Medium)
  --dry-run       preview what would be created without uploading anything
  --no-dedup      upload every result even if already ingested in a previous run
  --state-file    local file tracking already ingested ids (or THREATDOC_STATE_FILE,
                  defaults to ~/.threatdoc/seen.json)

Example:
  nuclei -u https://target.example -je results.json
  threatdoc ingest --tool nuclei --file results.json --report <id> --token <token>`)
}
