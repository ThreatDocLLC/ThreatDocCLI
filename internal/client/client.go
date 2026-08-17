package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"threatdoc-cli/internal/finding"
)

const cliVersion = "0.1.0"

type Client struct {
	BaseURL   string
	Token     string
	ReportKey string
	HTTP      *http.Client
}

func New(baseURL, token, reportKey string) *Client {
	return &Client{
		BaseURL:   baseURL,
		Token:     token,
		ReportKey: reportKey,
		HTTP:      &http.Client{Timeout: 15 * time.Second},
	}
}

type Result struct {
	Created     bool
	FindingID   string
	RateLimited bool
	Err         error
}

type apiResponse struct {
	FindingID string `json:"findingId"`
	Error     string `json:"error"`
}

func (c *Client) CreateFinding(reportID string, f finding.Finding) Result {
	body, err := json.Marshal(f)
	if err != nil {
		return Result{Err: fmt.Errorf("encoding finding: %w", err)}
	}

	url := fmt.Sprintf("%s/api/v1/reports/%s/findings", c.BaseURL, reportID)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Result{Err: fmt.Errorf("building request: %w", err)}
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "threatdoc-cli/"+cliVersion)
	if c.ReportKey != "" {
		req.Header.Set("X-Report-Key", c.ReportKey)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Result{Err: fmt.Errorf("request failed: %w", err)}
	}
	defer resp.Body.Close()

	var parsed apiResponse
	_ = json.NewDecoder(resp.Body).Decode(&parsed)

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return Result{RateLimited: true, Err: fmt.Errorf("rate limited: %s", parsed.Error)}
	case resp.StatusCode >= 400:
		return Result{Err: fmt.Errorf("%d: %s", resp.StatusCode, parsed.Error)}
	default:
		return Result{Created: true, FindingID: parsed.FindingID}
	}
}
