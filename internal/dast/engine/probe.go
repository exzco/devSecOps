package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	nmap "github.com/Ullaakut/nmap/v3"

	"devsecops/internal/dast/logger"
)

// ProbeResult 统一指纹探测结果结构
type ProbeResult struct {
	URL         string
	Proto       string
	Tags        []string
	RawResponse string
	Service     string
	Product     string
	Version     string
	CPEs        []string
	// Source 标记指纹来源：nmap / web / active_probe / fallback
	Source string
}

// FallbackTags 仅在所有探测路径均无结果时作为最终兜底使用
var FallbackTags = []string{"exposure", "misconfig", "config"}

// NmapBinaryProbe 对二进制协议端口执行精准 Nmap 服务指纹探测。
// 不包含任何退化链，失败直接返回 error，由调用方决策后续行为。
func NmapBinaryProbe(ctx context.Context, host string, port int) (ProbeResult, error) {
	hostPort := fmt.Sprintf("%s:%d", host, port)
	portStr := fmt.Sprintf("%d", port)

	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	scanner, err := nmap.NewScanner(probeCtx,
		nmap.WithTargets(host),
		nmap.WithPorts(portStr),
		nmap.WithServiceInfo(),
		nmap.WithVersionIntensity(5),
		nmap.WithSkipHostDiscovery(),
		nmap.WithDisabledDNSResolution(),
		nmap.WithScripts("banner"), // TCP socket 原始响应
	)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("[nmap-binary] create scanner failed: %w", err)
	}

	result, warnings, err := scanner.Run()
	if warnings != nil {
		for _, w := range *warnings {
			logger.Printf("[nmap-binary] warning on %s: %s\n", hostPort, w)
		}
	}
	if err != nil {
		return ProbeResult{}, fmt.Errorf("[nmap-binary] run failed on %s: %w", hostPort, err)
	}

	for _, nmapHost := range result.Hosts {
		for _, p := range nmapHost.Ports {
			if p.State.State != "open" {
				continue
			}

			svc := p.Service
			svcName := strings.ToLower(strings.TrimSpace(svc.Name))
			product := strings.TrimSpace(svc.Product)
			version := strings.TrimSpace(svc.Version)
			extraInfo := strings.TrimSpace(svc.ExtraInfo)
			osType := strings.TrimSpace(svc.OSType)
			deviceType := strings.TrimSpace(svc.DeviceType)
			isTunnel := strings.ToLower(strings.TrimSpace(svc.Tunnel)) == "ssl"

			proto, url := resolveProtoURL(svcName, isTunnel, hostPort)
			tags := buildTags(svcName, product, version, osType, deviceType, isTunnel, svc.CPEs)

			// 优先读取 banner 脚本原始响应
			var rawResp string
			for _, script := range p.Scripts {
				if script.ID == "banner" {
					rawResp = strings.TrimSpace(script.Output)
					break
				}
			}
			if rawResp == "" {
				rawResp = fmt.Sprintf(
					"service=%s product=%s version=%s osType=%s deviceType=%s extraInfo=%s cpes=%v confidence=%d",
					svcName, product, version, osType, deviceType, extraInfo, svc.CPEs, svc.Confidence,
				)
			}

			cpeStrings := make([]string, 0, len(svc.CPEs))
			for _, cpe := range svc.CPEs {
				cpeStrings = append(cpeStrings, string(cpe))
			}

			logger.Printf("[nmap-binary] %s → service=%s product=%s version=%s tags=%v\n",
				hostPort, svcName, product, version, tags)

			return ProbeResult{
				URL:         url,
				Proto:       proto,
				Tags:        tags,
				RawResponse: rawResp,
				Service:     svcName,
				Product:     product,
				Version:     version,
				CPEs:        cpeStrings,
				Source:      "nmap",
			}, nil
		}
	}

	return ProbeResult{}, fmt.Errorf("[nmap-binary] no open service detected on %s", hostPort)
}

// ActiveProbe 在 CDN 遮蔽或无特征防护场景下执行主动试探与 HTTP 降级盲测。
// 通过多种异常请求手法触发目标响应差异，从响应头/状态码/错误信息中提取指纹 tag。
func ActiveProbe(ctx context.Context, host string, port int) (ProbeResult, error) {
	hostPort := fmt.Sprintf("%s:%d", host, port)
	logger.Printf("[active-probe] starting CDN/featureless probe on %s\n", hostPort)

	tags := make(map[string]bool)
	var rawParts []string
	proto := "tcp"
	url := hostPort

	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// ── Step 1: 标准 HTTPS GET ──────────────────────────────────────────────
	if resp, err := doGet(probeCtx, client, "https://"+hostPort+"/"); err == nil {
		proto = "https"
		url = "https://" + hostPort
		tags["ssl"] = true
		tags["https"] = true
		tags["web"] = true
		extractHeaderTags(resp.Header, tags)
		statusTag := fmt.Sprintf("http-%d", resp.StatusCode)
		tags[statusTag] = true
		rawParts = append(rawParts, fmt.Sprintf("HTTPS_GET status=%d server=%q", resp.StatusCode, resp.Header.Get("Server")))
		resp.Body.Close()
	} else if resp2, err2 := doGet(probeCtx, client, "http://"+hostPort+"/"); err2 == nil {
		// ── Step 2: 标准 HTTP GET（HTTPS 失败后）──────────────────────────
		proto = "http"
		url = "http://" + hostPort
		tags["web"] = true
		tags["http"] = true
		extractHeaderTags(resp2.Header, tags)
		statusTag := fmt.Sprintf("http-%d", resp2.StatusCode)
		tags[statusTag] = true
		rawParts = append(rawParts, fmt.Sprintf("HTTP_GET status=%d server=%q", resp2.StatusCode, resp2.Header.Get("Server")))
		resp2.Body.Close()
	}

	// ── Step 3: HTTP/1.0 降级请求（移除 Host 头，探测原始协议差异）────────
	if banner, err := rawHTTP10Request(probeCtx, hostPort); err == nil && banner != "" {
		rawParts = append(rawParts, "HTTP1.0_DOWNGRADE: "+banner[:min(len(banner), 256)])
		extractBannerTags(banner, tags)
	}

	// ── Step 4: 格式异常请求（触发错误响应中的框架特征泄露）─────────────────
	if banner, err := malformedRequest(probeCtx, hostPort); err == nil && banner != "" {
		rawParts = append(rawParts, "MALFORMED_REQ: "+banner[:min(len(banner), 256)])
		extractBannerTags(banner, tags)
	}

	// ── Step 5: TLS 握手提取 SNI/CN（仅当已确认非 TLS 时跳过）─────────────
	if certInfo, err := tlsCertProbe(probeCtx, hostPort); err == nil && certInfo != "" {
		rawParts = append(rawParts, "TLS_CERT: "+certInfo)
		tags["ssl"] = true
		// 从证书 CN/SAN 中提取产品特征
		for _, word := range strings.Fields(strings.ToLower(certInfo)) {
			if len(word) >= 3 && !strings.Contains(word, ".") {
				tags[word] = true
			}
		}
	}

	tagList := mapToSlice(tags)
	if len(tagList) == 0 {
		tagList = FallbackTags
		logger.Printf("[active-probe] %s → all probes failed, using fallback tags\n", hostPort)
	} else {
		logger.Printf("[active-probe] %s → extracted tags=%v\n", hostPort, tagList)
	}

	return ProbeResult{
		URL:         url,
		Proto:       proto,
		Tags:        tagList,
		RawResponse: strings.Join(rawParts, " | "),
		Service:     proto,
		Source:      "active_probe",
	}, nil
}

// ────────────────────────────────────────────────────────────────────────────
// 内部辅助函数
// ────────────────────────────────────────────────────────────────────────────

func doGet(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")
	return client.Do(req)
}

// rawHTTP10Request 发送 HTTP/1.0 请求（无 Host 头），读取原始响应前 512 字节
func rawHTTP10Request(ctx context.Context, hostPort string) (string, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, _ = fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")

	buf := make([]byte, 512)
	n, _ := io.ReadAtLeast(conn, buf, 1)
	if n == 0 {
		return "", fmt.Errorf("empty response")
	}
	return string(buf[:n]), nil
}

// malformedRequest 发送格式异常请求，触发框架错误页面中的特征泄露
func malformedRequest(ctx context.Context, hostPort string) (string, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 发送协议版本不存在的请求
	_, _ = fmt.Fprintf(conn, "HELLO / HTTP/9.9\r\nHost: %s\r\n\r\n", hostPort)

	buf := make([]byte, 512)
	n, _ := io.ReadAtLeast(conn, buf, 1)
	if n == 0 {
		return "", fmt.Errorf("empty response")
	}
	return string(buf[:n]), nil
}

// tlsCertProbe 执行 TLS 握手，提取证书 CN 和 SAN 信息
func tlsCertProbe(ctx context.Context, hostPort string) (string, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config:    &tls.Config{InsecureSkipVerify: true},
	}
	conn, err := dialer.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return "", fmt.Errorf("not a tls conn")
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("no peer certificate")
	}
	cert := certs[0]
	parts := []string{"CN=" + cert.Subject.CommonName}
	for _, san := range cert.DNSNames {
		parts = append(parts, "SAN="+san)
	}
	return strings.Join(parts, " "), nil
}

// extractHeaderTags 从 HTTP 响应头提取技术栈 tag
func extractHeaderTags(header http.Header, tags map[string]bool) {
	// Server 头
	if server := header.Get("Server"); server != "" {
		for _, word := range strings.Fields(strings.ToLower(server)) {
			word = strings.Trim(word, "/.()")
			if len(word) >= 2 {
				tags[word] = true
			}
		}
	}
	// X-Powered-By
	if xpb := header.Get("X-Powered-By"); xpb != "" {
		for _, word := range strings.Fields(strings.ToLower(xpb)) {
			word = strings.Trim(word, "/.()")
			if len(word) >= 2 {
				tags[word] = true
			}
		}
	}
	// X-Generator / X-Frame-Options 等次要头
	for _, h := range []string{"X-Generator", "X-AspNet-Version", "X-Runtime", "Via"} {
		if val := header.Get(h); val != "" {
			tags[strings.ToLower(strings.Fields(val)[0])] = true
		}
	}
	// Set-Cookie 中的框架特征（PHPSESSID / JSESSIONID / ASP.NET_SessionId）
	for _, cookie := range header.Values("Set-Cookie") {
		lower := strings.ToLower(cookie)
		switch {
		case strings.Contains(lower, "phpsessid"):
			tags["php"] = true
		case strings.Contains(lower, "jsessionid"):
			tags["java"] = true
			tags["tomcat"] = true
		case strings.Contains(lower, "asp.net_sessionid"):
			tags["asp.net"] = true
			tags["iis"] = true
		case strings.Contains(lower, "laravel_session"):
			tags["laravel"] = true
			tags["php"] = true
		case strings.Contains(lower, "ci_session"):
			tags["codeigniter"] = true
			tags["php"] = true
		}
	}
}

// extractBannerTags 从原始 TCP banner 中提取服务特征 tag
func extractBannerTags(banner string, tags map[string]bool) {
	lower := strings.ToLower(banner)
	keywords := map[string][]string{
		"nginx":    {"nginx"},
		"apache":   {"apache", "httpd"},
		"iis":      {"iis", "microsoft-iis"},
		"tomcat":   {"tomcat", "apache-coyote"},
		"php":      {"php"},
		"python":   {"python", "werkzeug", "django", "flask", "gunicorn"},
		"node":     {"node.js", "express"},
		"java":     {"java", "jetty"},
		"openssl":  {"openssl"},
		"openssh":  {"openssh"},
		"ftp":      {"ftp", "vsftpd", "proftpd", "filezilla"},
		"smtp":     {"smtp", "postfix", "exim", "sendmail"},
		"redis":    {"redis"},
		"mysql":    {"mysql", "mariadb"},
		"postgres": {"postgresql"},
	}
	for tag, patterns := range keywords {
		for _, p := range patterns {
			if strings.Contains(lower, p) {
				tags[tag] = true
			}
		}
	}
}

func mapToSlice(m map[string]bool) []string {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ────────────────────────────────────────────────────────────────────────────
// 以下函数从 fingerprint.go 迁移，供 probe.go 内部使用
// ────────────────────────────────────────────────────────────────────────────

func normalizeTag(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, " ", "-")
	return name
}

func resolveProtoURL(svcName string, isTunnel bool, hostPort string) (proto, url string) {
	if isTunnel || svcName == "https" || strings.Contains(svcName, "ssl") {
		return "https", "https://" + hostPort
	}
	if svcName == "http" || strings.HasPrefix(svcName, "http") {
		return "http", "http://" + hostPort
	}
	return "tcp", hostPort
}

// buildTags 从 nmap 服务信息提取精准 tag 集合（CPE > product > svcName > OS/DeviceType）
func buildTags(svcName, product, version, osType, deviceType string, isTunnel bool, cpes []nmap.CPE) []string {
	if svcName == "" || svcName == "unknown" {
		return FallbackTags
	}

	tagSet := make(map[string]bool)

	// 1. CPE 解析（最精准）cpe:/a:vendor:product:version
	for _, cpe := range cpes {
		parts := strings.Split(string(cpe), ":")
		if len(parts) >= 4 {
			if p := strings.ToLower(parts[3]); p != "" && p != "*" {
				tagSet[p] = true
			}
		}
		if len(parts) >= 3 {
			if v := strings.ToLower(parts[2]); v != "" && v != "*" {
				tagSet[v] = true
			}
		}
	}

	// 2. product 字段拆词
	if product != "" {
		for _, word := range strings.Fields(product) {
			if tag := normalizeTag(word); len(tag) >= 2 {
				tagSet[tag] = true
			}
		}
	}

	// 3. svcName 本身
	tagSet[svcName] = true

	// 4. 版本号
	if version != "" {
		tagSet[version] = true
	}

	// 5. OSType / DeviceType
	if osType != "" {
		tagSet[normalizeTag(osType)] = true
	}
	if deviceType != "" {
		tagSet[normalizeTag(deviceType)] = true
	}

	// 6. 协议族补充 tag
	switch {
	case svcName == "http" || strings.HasPrefix(svcName, "http"):
		tagSet["web"] = true
	case isTunnel || svcName == "https" || strings.Contains(svcName, "ssl"):
		tagSet["http"] = true
		tagSet["ssl"] = true
		tagSet["web"] = true
	case svcName == "ftp", svcName == "sftp":
		tagSet["network"] = true
	case svcName == "mysql", svcName == "postgresql", svcName == "mssql",
		svcName == "oracle-tns", svcName == "ms-sql-s":
		tagSet["database"] = true
	case svcName == "redis", svcName == "memcached", svcName == "mongodb":
		tagSet["database"] = true
	case svcName == "smtp", svcName == "imap", svcName == "pop3":
		tagSet["mail"] = true
	case svcName == "rdp", svcName == "ms-wbt-server":
		tagSet["rdp"] = true
		tagSet["windows"] = true
	case svcName == "ldap", svcName == "ldaps":
		tagSet["ldap"] = true
	case svcName == "smb", svcName == "microsoft-ds", svcName == "netbios-ssn":
		tagSet["smb"] = true
		tagSet["windows"] = true
	}

	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	return tags
}
