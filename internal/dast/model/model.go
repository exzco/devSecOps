package model

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

type Target struct {
	Host            string `json:"host"`
	Port            int    `json:"port,omitempty"`
	Kind            string `json:"kind"`
	IsValid         bool   `json:"is_valid"`
	ValidationError string `json:"validation_error,omitempty"`
}

func ParseTarget(raw string) *Target {
	trimmed := strings.TrimSpace(raw)
	target := &Target{IsValid: true}
	if trimmed == "" {
		target.IsValid = false
		target.ValidationError = "empty target string"
		return target
	}

	if strings.Contains(trimmed, "://") {
		u, err := url.Parse(trimmed)
		if err != nil || u.Hostname() == "" {
			target.IsValid = false
			target.ValidationError = fmt.Sprintf("invalid url format: %v", err)
			return target
		}
		target.Kind = "URL"
		scheme := strings.ToLower(u.Scheme)
		target.Host = strings.ToLower(u.Hostname())
		if u.Port() != "" {
			target.Port, err = strconv.Atoi(u.Port())
			if err != nil || target.Port < 1 || target.Port > 65535 {
				target.IsValid = false
				target.ValidationError = "invalid port in url"
				return target
			}
		} else if scheme == "https" {
			target.Port = 443
		} else if scheme == "http" {
			target.Port = 80
		}
		return target
	}

	if strings.Contains(trimmed, "/") {
		if _, _, err := net.ParseCIDR(trimmed); err != nil {
			target.IsValid = false
			target.ValidationError = "invalid cidr format"
			return target
		}
		target.Kind = "CIDR"
		target.Host = trimmed
		return target
	}

	if host, port, err := net.SplitHostPort(trimmed); err == nil {
		if p, parseErr := strconv.Atoi(port); parseErr == nil && p >= 1 && p <= 65535 {
			target.Kind = "HOST_PORT"
			target.Host = strings.ToLower(host)
			target.Port = p
			return target
		}
	}

	if net.ParseIP(trimmed) != nil {
		target.Kind = "IP"
		target.Host = trimmed
		return target
	}

	target.Kind = "DOMAIN"
	target.Host = strings.ToLower(trimmed)
	return target
}

type TLSInfo struct {
	Version     string    `json:"version"`
	CipherSuite string    `json:"cipher_suite"`
	SubjectCN   string    `json:"subject_cn"`
	DNSNames    []string  `json:"dns_names"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	IsExpired   bool      `json:"is_expired"`
	ALPN        []string  `json:"alpn,omitempty"`
}

type Service struct {
	Host       string            `json:"host"`
	Port       int               `json:"port"`
	Transport  string            `json:"transport"`
	Protocol   string            `json:"protocol"`
	Product    string            `json:"product,omitempty"`
	Version    string            `json:"version,omitempty"`
	Banner     string            `json:"banner,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	RawDetails map[string]any    `json:"raw_details,omitempty"`
	TLS        *TLSInfo          `json:"tls,omitempty"`
	ObservedAt time.Time         `json:"observed_at"`
}

type PortObservation struct {
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Transport   string    `json:"transport"`
	Status      string    `json:"status"`
	DurationMs  int64     `json:"duration_ms"`
	ProbeSource string    `json:"probe_source"`
	ObservedAt  time.Time `json:"observed_at"`
}

type Finding struct {
	ID          string   `json:"id"`
	ScanRunID   string   `json:"scan_run_id"`
	StableKey   string   `json:"stable_key"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	CheckID     string   `json:"check_id"`
	MatchedAt   string   `json:"matched_at"`
	CWE         []string `json:"cwe,omitempty"`
}

func GenerateStableFindingKey(asset, endpoint, checkID, parameter, variant string) string {
	raw := strings.Join([]string{asset, endpoint, checkID, parameter, variant}, "|")
	hash := sha256.Sum256([]byte(strings.ToLower(raw)))
	return fmt.Sprintf("%x", hash)
}

type Policy struct {
	MaxRPS             int      `json:"max_rps"`
	MaxDurationMinutes int      `json:"max_duration_minutes"`
	MaxRequestsTotal   int64    `json:"max_requests_total"`
	PortProfile        string   `json:"port_profile"`
	PortTimeoutSec     int      `json:"port_timeout_sec"`
	DeniedTags         []string `json:"denied_tags,omitempty"`
}

func DefaultPolicy() *Policy {
	return &Policy{
		MaxRPS:             50,
		MaxDurationMinutes: 60,
		MaxRequestsTotal:   10000,
		PortProfile:        "balanced",
		PortTimeoutSec:     5,
		DeniedTags:         []string{"dos", "fuzz"},
	}
}

type CheckSpec struct {
	ID       string   `json:"id"`
	FilePath string   `json:"file_path"`
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	Tags     []string `json:"tags"`
}

func NewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func NowUTC() time.Time {
	return time.Now().UTC()
}

func normalizePrefix(prefix string) string {
	if prefix == "" {
		return "scan"
	}
	return prefix
}

func StatusKey(prefix, taskID string) string  { return normalizePrefix(prefix) + ":status:" + taskID }
func ResultsKey(prefix, taskID string) string { return normalizePrefix(prefix) + ":results:" + taskID }
func FindingsKey(prefix, taskID string) string {
	return normalizePrefix(prefix) + ":findings:" + taskID
}
func AssetsKey(prefix, taskID string) string  { return normalizePrefix(prefix) + ":assets:" + taskID }
func TargetsKey(prefix, taskID string) string { return normalizePrefix(prefix) + ":targets:" + taskID }
func ConfigKey(prefix, configID string) string {
	return normalizePrefix(prefix) + ":config:" + configID
}
func AllConfigsKey(prefix string) string { return normalizePrefix(prefix) + ":all_configs" }
func AllTasksKey(prefix string) string   { return normalizePrefix(prefix) + ":all_tasks" }
