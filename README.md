# ThreatDocCLI
Pushes parsed scanner output into a ThreatDoc report's findings.

Get a token from ThreatDoc's Engagement Workspace > CLI Convert tab
Token expire after 60 minutes and only work against the one report generated under

## Build 

Requires GO 1.21+. No external dependencies

```sh
cd cli
go build -o threatdoc .
```
## Usage

```sh
nuclei - u https://example.com -je results.json

./threatdoc ingest --tool nuclei --file results.json --report <reportID> --token <token>
```

or 

```sh
nuclie -u https://example.com -je - | ./threatdoc ingest --tool nuclie -- report <reportID> --token <token>
```

`--report` and `--token` can be set as env `THREATDOC_REPORT_ID` and `THREATDOC_TOKEN`

## Rescanned 

If a tool provides a stable id field that CLI records what's already been uploaded in a local file (`~/.threatdoc/seen.json` by default) and skips those ids. This is local to the machine that ran it, it won't help if a teammate or different machine ingests the same export.

Pass `--no-dedup` to upload everything or `--state-file <path>` to point at a different tracking file

## Supported tools

- **nuclie** reads `-je`/`-json-export` output
- **burp** reads Burp Scanner's XML issue export (Dashboard > select issues + right click > "Report selected issues" > XML). False positive are dropped from ingesting
- **zap** reads OWASP ZAP's XML report (Report > Generate Report > XML, or `zap-basline.py`/`zap-full-scan.py` with `-x`) False positives like `confidence` 0 are dropped from ingesting
- **nessus** reads `.nessus` scan export (File > Export > Nessus)
- **prowler** reads Prowler's native JSON output `prowler aws -M json`
- **trivy** reads `trivy image -f json` / `trivy fs -f json` output. Only `Vulnerabilities` array are handled at the moment
