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

	"devsecops/internal/dast/logger"
)

// WebFingerprint 对 Web 流量端口执行深度指纹识别：
//  1. 使用标准 http.Client 采集响应头、响应体前 4096 字节、TLS 证书信息
//  2. 将响应头+体传给 wappalyzergo 进行技术栈识别
//  3. 从识别结果提取 tag 列表，并补充头部特征 tag
func WebFingerprint(ctx context.Context, host string, port int, isTLS bool) (ProbeResult, error) {
	hostPort := fmt.Sprintf("%s:%d", host, port)

	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	targetURL := fmt.Sprintf("%s://%s/", scheme, hostPort)

	logger.Printf("[webfp] probing %s\n", targetURL)

	fpCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 跟随最多 3 次重定向
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(fpCtx, "GET", targetURL, nil)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("[webfp] create request failed: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		// 若 https 失败，自动尝试降级到 http
		if isTLS {
			logger.Printf("[webfp] HTTPS failed for %s, retrying HTTP: %v\n", hostPort, err)
			return WebFingerprint(ctx, host, port, false)
		}
		return ProbeResult{}, fmt.Errorf("[webfp] HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应体前 4096 字节用于 DOM 特征分析
	bodyBuf := make([]byte, 4096)
	n, _ := io.ReadAtLeast(resp.Body, bodyBuf, 1)
	// 读完剩余 body 防止连接复用问题
	_, _ = io.Copy(io.Discard, resp.Body)
	bodyBytes := bodyBuf[:n]

	// ── Wappalyzer 技术栈识别 ───────────────────────────────────────────
	wappalyzer, err := wappalyzergo.New()
	if err != nil {
		return ProbeResult{}, fmt.Errorf("[webfp] wappalyzer init failed: %w", err)
	}

	// 将 http.Header 转换为 map[string][]string（wappalyzer 接受该格式）
	fingerprints := wappalyzer.Fingerprint(resp.Header, bodyBytes)

	tags := make(map[string]bool)

	// 从 wappalyzer 识别结果提取 tag（产品名 → 标准化 tag）
	for app := range fingerprints {
		tag := strings.ToLower(strings.ReplaceAll(app, " ", "-"))
		tags[tag] = true
	}

	// 补充协议层 tag
	tags["web"] = true
	if isTLS || scheme == "https" {
		tags["ssl"] = true
		tags["https"] = true
	} else {
		tags["http"] = true
	}

	// 补充响应头特征 tag（作为 wappalyzer 的补充）
	extractHeaderTags(resp.Header, tags)

	// TLS 证书信息（补充 tag）
	var certInfo string
	if isTLS {
		if ci, err := tlsCertProbe(fpCtx, hostPort); err == nil {
			certInfo = ci
			// 从证书提取产品特征（简单文本匹配）
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

	// 构建 RawResponse 摘要
	serverHeader := resp.Header.Get("Server")
	poweredBy := resp.Header.Get("X-Powered-By")
	rawResp := fmt.Sprintf(
		"status=%d server=%q x-powered-by=%q wappalyzer=%v cert=%q body_prefix=%q",
		resp.StatusCode, serverHeader, poweredBy,
		fingerprintKeys(fingerprints),
		certInfo,
		truncate(string(bodyBytes), 128),
	)

	logger.Printf("[webfp] %s → status=%d wappalyzer=%v tags=%v\n",
		targetURL, resp.StatusCode, fingerprintKeys(fingerprints), tagList)

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

// fingerprintKeys 返回 wappalyzer fingerprint map 的 key 列表（已识别的应用名）
func fingerprintKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
