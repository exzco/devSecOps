package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/chainreactors/fingers"

	"devsecops/internal/model"
)

var (
	hrefRegex    = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'>\s#]+)["']`)
	apiPathRegex = regexp.MustCompile(`(?i)["'](/(?:api|v[0-9]|rest|admin|user|auth|login|manage|health|actuator|metrics|status)[a-zA-Z0-9_\-/\.]*)["']`)
)

type HTTPResponse struct {
	StatusCode int
	Headers    map[string]string
	RawHeader  http.Header
	Body       string
	RawBytes   []byte
	DurationMs int64
}

type FingerprintHTTPClient struct {
	client *http.Client
}

func NewFingerprintHTTPClient(timeout time.Duration) *FingerprintHTTPClient {
	c := NewHTTPClient(timeout)
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	return &FingerprintHTTPClient{
		client: c,
	}
}

func (c *FingerprintHTTPClient) Do(ctx context.Context, method, targetURL string, headers map[string]string, body string) (*HTTPResponse, error) {
	start := time.Now()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	rawBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	respHeaders := make(map[string]string)
	for k := range resp.Header {
		respHeaders[strings.ToLower(k)] = resp.Header.Get(k)
	}

	return &HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		RawHeader:  resp.Header,
		Body:       string(rawBytes),
		RawBytes:   rawBytes,
		DurationMs: time.Since(start).Milliseconds(),
	}, nil
}

type TLSAnalyzer struct {
	timeout time.Duration
}

func NewTLSAnalyzer(timeout time.Duration) *TLSAnalyzer {
	return &TLSAnalyzer{timeout: timeout}
}

func (a *TLSAnalyzer) AnalyzeTLS(ctx context.Context, host string, port int) (*model.TLSInfo, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := NewDialer(a.timeout)

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates presented")
	}

	cert := state.PeerCertificates[0]
	now := time.Now()

	versionStr := "TLS 1.2"
	switch state.Version {
	case tls.VersionTLS10:
		versionStr = "TLS 1.0"
	case tls.VersionTLS11:
		versionStr = "TLS 1.1"
	case tls.VersionTLS12:
		versionStr = "TLS 1.2"
	case tls.VersionTLS13:
		versionStr = "TLS 1.3"
	}

	return &model.TLSInfo{
		Version:     versionStr,
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		SubjectCN:   cert.Subject.CommonName,
		DNSNames:    cert.DNSNames,
		Issuer:      cert.Issuer.CommonName,
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		IsExpired:   now.Before(cert.NotBefore) || now.After(cert.NotAfter),
		ALPN:        []string{state.NegotiatedProtocol},
	}, nil
}

type FingerprintEngine struct {
	engine *fingers.Engine
}

func NewFingerprintEngine() *FingerprintEngine {
	engine, err := fingers.NewEngine()
	if err != nil {
		fmt.Printf("[-] Failed to initialize fingers engine: %v\n", err)
	}
	return &FingerprintEngine{
		engine: engine,
	}
}

func (fe *FingerprintEngine) DetectWebTechnologies(resp *HTTPResponse) string {
	if fe.engine == nil || resp == nil || len(resp.RawBytes) == 0 {
		return ""
	}

	scanBytes := resp.RawBytes
	if len(scanBytes) > 128*1024 {
		scanBytes = scanBytes[:128*1024]
	}

	frames := fe.engine.WebMatchWithEngines(scanBytes, "fingers", "wappalyzer", "fingerprinthub", "ehole", "goby")

	for _, frame := range frames {
		return frame.Name
	}
	return ""
}

func ExtractEndpointsFromHTML(baseURL *url.URL, htmlBody string) []string {
	seen := make(map[string]bool)
	var endpoints []string

	matches := hrefRegex.FindAllStringSubmatch(htmlBody, -1)
	for _, m := range matches {
		if len(m) > 1 {
			rel := strings.TrimSpace(m[1])
			if rel != "" && !strings.HasPrefix(rel, "javascript:") && !strings.HasPrefix(rel, "mailto:") {
				parsed, err := url.Parse(rel)
				if err == nil {
					resolved := baseURL.ResolveReference(parsed)
					if resolved.Host == baseURL.Host {
						cleanURL := resolved.Scheme + "://" + resolved.Host + resolved.Path
						if !seen[cleanURL] {
							seen[cleanURL] = true
							endpoints = append(endpoints, cleanURL)
						}
					}
				}
			}
		}
	}

	apiMatches := apiPathRegex.FindAllStringSubmatch(htmlBody, -1)
	for _, m := range apiMatches {
		if len(m) > 1 {
			p := m[1]
			cleanURL := baseURL.Scheme + "://" + baseURL.Host + p
			if !seen[cleanURL] {
				seen[cleanURL] = true
				endpoints = append(endpoints, cleanURL)
			}
		}
	}

	return endpoints
}
