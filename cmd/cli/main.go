package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const version = "2.0.0"

type httpClient struct {
	baseURL string
	client  *http.Client
}

func newHTTPClient(server string) *httpClient {
	server = strings.TrimRight(strings.TrimSpace(server), "/")
	if server == "" {
		server = strings.TrimRight(os.Getenv("DEVSECOPS_SERVER"), "/")
	}
	if server == "" {
		server = "http://localhost:22211"
	}
	return &httpClient{
		baseURL: server,
		client:  &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *httpClient) do(method, endpoint string, requestBody any) ([]byte, error) {
	data, err := c.doRequest(c.baseURL, method, endpoint, requestBody)
	if err != nil && strings.Contains(c.baseURL, "localhost") && strings.Contains(err.Error(), "connection refused") {
		// Dual-stack loopback fallback (WSL2/Linux IPv6 fallback)
		fallbackURL := strings.Replace(c.baseURL, "localhost", "[::1]", 1)
		if fallbackData, fallbackErr := c.doRequest(fallbackURL, method, endpoint, requestBody); fallbackErr == nil {
			c.baseURL = fallbackURL
			return fallbackData, nil
		}
	}
	return data, err
}

func (c *httpClient) doRequest(baseURL, method, endpoint string, requestBody any) ([]byte, error) {
	var body io.Reader
	if requestBody != nil {
		data, err := json.Marshal(requestBody)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, baseURL+endpoint, body)
	if err != nil {
		return nil, err
	}
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return data, nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "scan":
		runScanCommand(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fail(2, "unknown command: %s", os.Args[1])
	}
}

func printUsage() {
	fmt.Print(`devsecops-cli - thin CI/CD client

Usage:
  devsecops-cli scan submit --type sast --repo-id 1 --language java
  devsecops-cli scan submit --type dast --target https://staging.example.com
  devsecops-cli scan submit --type sca --repo-id 1
  devsecops-cli scan submit --type sca --target /path/to/project
  devsecops-cli scan wait --scan-id sca:1
  devsecops-cli scan run --type sca --target /path/to/project

Environment:
  DEVSECOPS_SERVER   Platform base URL (default: http://localhost:22211)

Exit codes:
  0  success
  1  scan failure
  2  usage, network, or platform error
`)
}

func runScanCommand(args []string) {
	if len(args) == 0 {
		printUsage()
		os.Exit(2)
	}

	switch args[0] {
	case "submit":
		runSubmit(args[1:], false)
	case "run":
		runSubmit(args[1:], true)
	case "wait":
		runWait(args[1:])
	default:
		fail(2, "unknown scan command: %s", args[0])
	}
}

type submitRequest struct {
	Type        string   `json:"type"`
	RepoID      uint     `json:"repo_id,omitempty"`
	Branch      string   `json:"branch,omitempty"`
	Language    string   `json:"language,omitempty"`
	QuerySuite  string   `json:"query_suite,omitempty"`
	RuleProfile string   `json:"rule_profile,omitempty"`
	Rules       []string `json:"rules,omitempty"`
	Target      string   `json:"target,omitempty"`
	Ports       string   `json:"ports,omitempty"`
	TaskName    string   `json:"task_name,omitempty"`
}

type apiResponse struct {
	Data json.RawMessage `json:"data"`
}

func runSubmit(args []string, waitForCompletion bool) {
	fs := flag.NewFlagSet("scan submit", flag.ExitOnError)
	server := fs.String("server", "", "DevSecOps platform URL")
	scanType := fs.String("type", "", "Scan type: sast, dast, or sca")
	repoID := fs.Uint("repo-id", 0, "Registered repository ID for SAST/SCA")
	branch := fs.String("branch", "main", "Git branch for SAST/SCA")
	language := fs.String("language", "", "Repository language for SAST/SCA")
	querySuite := fs.String("query-suite", "", "Comma-separated CodeQL query suite paths")
	ruleProfile := fs.String("rule-profile", "baseline", "CodeQL rule profile")
	rules := fs.String("rules", "", "Comma-separated CWE rule tags")
	target := fs.String("target", "", "URL, host, or CIDR target for DAST, or workspace path for SCA")
	ports := fs.String("ports", "", "DAST port range")
	taskName := fs.String("name", "", "Human-readable DAST task name")
	timeout := fs.Duration("timeout", 45*time.Minute, "Total run timeout")
	interval := fs.Duration("interval", 3*time.Second, "Status polling interval")
	_ = fs.Parse(args)

	kind := strings.ToLower(strings.TrimSpace(*scanType))
	if kind != "sast" && kind != "dast" && kind != "sca" {
		fail(2, "--type must be sast, dast, or sca")
	}

	req := submitRequest{
		Type:        kind,
		Branch:      strings.TrimSpace(*branch),
		Language:    strings.TrimSpace(*language),
		QuerySuite:  strings.TrimSpace(*querySuite),
		RuleProfile: strings.TrimSpace(*ruleProfile),
		Rules:       splitCSV(*rules),
		Target:      strings.TrimSpace(*target),
		Ports:       strings.TrimSpace(*ports),
		TaskName:    strings.TrimSpace(*taskName),
	}
	if kind == "sast" {
		if *repoID == 0 {
			fail(2, "--repo-id is required for SAST")
		}
		if req.Language == "" {
			fail(2, "--language is required for SAST")
		}
		req.RepoID = *repoID
	} else if kind == "dast" {
		if req.Target == "" {
			fail(2, "--target is required for DAST")
		}
	} else if kind == "sca" {
		if *repoID == 0 && req.Target == "" {
			fail(2, "either --repo-id or --target is required for SCA")
		}
		if *repoID != 0 {
			req.RepoID = *repoID
		}
	}

	client := newHTTPClient(*server)
	body, err := client.do(http.MethodPost, "/api/v1/scans", req)
	if err != nil {
		fail(2, "submit scan: %v", err)
	}

	var envelope apiResponse
	if err := json.Unmarshal(body, &envelope); err != nil {
		fail(2, "decode submit response: %v", err)
	}
	var result struct {
		ScanID string `json:"scan_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		fail(2, "decode submit data: %v", err)
	}
	if result.ScanID == "" {
		fail(2, "platform response did not include scan_id")
	}

	fmt.Printf("scan_id=%s status=%s\n", result.ScanID, result.Status)
	if !waitForCompletion {
		return
	}

	status := waitForScan(client, result.ScanID, *timeout, *interval)
	if !isSuccessfulStatus(status) {
		fail(1, "scan finished with status %s", status)
	}
	fmt.Printf("scan_id=%s finished successfully\n", result.ScanID)
}

func runWait(args []string) {
	fs := flag.NewFlagSet("scan wait", flag.ExitOnError)
	server := fs.String("server", "", "DevSecOps platform URL")
	scanID := fs.String("scan-id", "", "Unified scan ID, for example sast:1, dast:task-id, or sca:1")
	timeout := fs.Duration("timeout", 45*time.Minute, "Polling timeout")
	interval := fs.Duration("interval", 3*time.Second, "Status polling interval")
	_ = fs.Parse(args)

	if strings.TrimSpace(*scanID) == "" {
		fail(2, "--scan-id is required")
	}
	status := waitForScan(newHTTPClient(*server), *scanID, *timeout, *interval)
	fmt.Printf("scan_id=%s status=%s\n", *scanID, status)
	if !isSuccessfulStatus(status) {
		fail(1, "scan finished with status %s", status)
	}
}

func waitForScan(client *httpClient, scanID string, timeout, interval time.Duration) string {
	deadline := time.Now().Add(timeout)
	for {
		body, err := client.do(http.MethodGet, "/api/v1/scans/"+scanID, nil)
		if err != nil {
			fail(2, "query scan status: %v", err)
		}

		var envelope apiResponse
		if err := json.Unmarshal(body, &envelope); err != nil {
			fail(2, "decode scan status response: %v", err)
		}
		var result struct {
			Status   string `json:"status"`
			Finished bool   `json:"finished"`
			Error    string `json:"error"`
		}
		if err := json.Unmarshal(envelope.Data, &result); err != nil {
			fail(2, "decode scan status payload: %v", err)
		}

		if result.Finished {
			if result.Error != "" {
				fmt.Fprintf(os.Stderr, "platform error: %s\n", result.Error)
			}
			return result.Status
		}

		if time.Now().After(deadline) {
			fail(1, "timeout waiting for scan %s", scanID)
		}
		time.Sleep(interval)
	}
}

func splitCSV(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

func isSuccessfulStatus(status string) bool {
	switch strings.ToLower(status) {
	case "success", "completed":
		return true
	default:
		return false
	}
}

func fail(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(code)
}
