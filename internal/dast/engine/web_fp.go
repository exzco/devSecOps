package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	wappalyzergo "github.com/projectdiscovery/wappalyzergo"

	"devsecops/pkg/logger"
)

func WebFingerprint(ctx context.Context, host string, port int, isTLS bool) (ProbeResult, error) {
	hostPort := fmt.Sprintf("%s:%d", host, port)

	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	targetURL := fmt.Sprintf("%s://%s/", scheme, hostPort)
	logger.DAST("WebFP", "probing %s", targetURL)

	fpCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(fpCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("[webfp] create request failed: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		if isTLS {
			logger.DAST("WebFP", "HTTPS failed for %s, retrying HTTP: %v", hostPort, err)
			return WebFingerprint(ctx, host, port, false)
		}
		return ProbeResult{}, fmt.Errorf("[webfp] HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBuf := make([]byte, 4096)
	n, _ := io.ReadAtLeast(resp.Body, bodyBuf, 1)
	_, _ = io.Copy(io.Discard, resp.Body)
	bodyBytes := bodyBuf[:n]

	wappalyzer, err := wappalyzergo.New()
	if err != nil {
		return ProbeResult{}, fmt.Errorf("[webfp] wappalyzer init failed: %w", err)
	}

	fingerprints := wappalyzer.Fingerprint(resp.Header, bodyBytes)
	tags := make(map[string]bool)
	for app := range fingerprints {
		tags[strings.ToLower(strings.ReplaceAll(app, " ", "-"))] = true
	}

	tags["web"] = true
	if isTLS || scheme == "https" {
		tags["ssl"] = true
		tags["https"] = true
	} else {
		tags["http"] = true
	}

	extractHeaderTags(resp.Header, tags)

	var certInfo string
	if isTLS {
		if ci, err := tlsCertProbe(fpCtx, hostPort); err == nil {
			certInfo = ci
			for _, word := range strings.Fields(strings.ToLower(ci)) {
				word = strings.Trim(word, "=,.")
				if len(word) >= 3 && !strings.Contains(word, ".") && word != "cn" && word != "san" {
					tags[word] = true
				}
			}
		}
	}

	tagList := mapToSlice(tags)
	if len(tagList) == 0 {
		return ProbeResult{}, fmt.Errorf("[webfp] no fingerprint identified for %s", targetURL)
	}

	serverHeader := resp.Header.Get("Server")
	poweredBy := resp.Header.Get("X-Powered-By")
	rawResp := fmt.Sprintf(
		"status=%d server=%q x-powered-by=%q wappalyzer=%v cert=%q body_prefix=%q",
		resp.StatusCode,
		serverHeader,
		poweredBy,
		fingerprintKeys(fingerprints),
		certInfo,
		truncate(string(bodyBytes), 128),
	)

	logger.DAST("WebFP", "%s -> status=%d wappalyzer=%v tags=%v", targetURL, resp.StatusCode, fingerprintKeys(fingerprints), tagList)

	return ProbeResult{
		URL:         fmt.Sprintf("%s://%s", scheme, hostPort),
		Proto:       scheme,
		Tags:        tagList,
		RawResponse: rawResp,
		Service:     "http",
		Product:     strings.Join(fingerprintKeys(fingerprints), ","),
		Source:      "web",
	}, nil
}

func fingerprintKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
