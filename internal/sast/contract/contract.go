package contract

import "encoding/json"

type Job struct {
	TaskID      uint   `json:"task_id"`
	RepoID      uint   `json:"repo_id"`
	RepoURL     string `json:"repo_url"`
	Branch      string `json:"branch"`
	Language    string `json:"language"`
	AuthType    string `json:"auth_type"`
	AuthSecret  string `json:"auth_secret"`
	QuerySuite  string `json:"query_suite"`
	RuleProfile string `json:"rule_profile"`
	Rules       string `json:"rules"`
	CommitSHA   string `json:"commit_sha,omitempty"`
}

type Callback struct {
	Message         string          `json:"message,omitempty"`
	Error           string          `json:"error,omitempty"`
	SARIF           json.RawMessage `json:"sarif,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	DurationMs      int64           `json:"duration_ms,omitempty"`
	CommitSHA       string          `json:"commit_sha,omitempty"`
	WorkerID        string          `json:"worker_id,omitempty"`
}

type Vulnerability struct {
	RuleID      string       `json:"rule_id"`
	RuleName    string       `json:"rule_name"`
	Severity    string       `json:"severity"`
	FilePath    string       `json:"file_path"`
	StartLine   int          `json:"start_line"`
	EndLine     int          `json:"end_line"`
	CodeSnippet string       `json:"code_snippet"`
	Message     string       `json:"message"`
	DataFlow    [][]FlowStep `json:"data_flow"`
	Fingerprint string       `json:"fingerprint"`
}

type FlowStep struct {
	FilePath  string `json:"file_path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Message   string `json:"message"`
	Snippet   string `json:"snippet"`
}
