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

	"devsecops/pkg/logger"
)

type ProbeResult struct {
	URL         string
	Proto       string
	Tags        []string
	RawResponse string
	Service     string
	Product     string
	Version     string
	CPEs        []string
	Source      string
}

var FallbackTags = []string{"exposure", "misconfig", "config"}

func NmapBinaryProbe(ctx context.Context, host string, port int) (ProbeResult, error) {
	hostPort := fmt.Sprintf("%s:%d", host, port)
	portStr := fmt.Sprintf("%d", port)

	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	scanner, err := nmap.NewScanner(
		probeCtx,
		nmap.WithTargets(host),
		nmap.WithPorts(portStr),
		nmap.WithServiceInfo(),
		nmap.WithVersionIntensity(5),
		nmap.WithSkipHostDiscovery(),
		nmap.WithDisabledDNSResolution(),
		nmap.WithScripts("banner"),
	)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("[nmap-binary] create scanner failed: %w", err)
	}

	result, warnings, err := scanner.Run()
	if warnings != nil {
		for _, warning := range *warnings {
			logger.DAST("Nmap", "warning on %s: %s", hostPort, warning)
		}
	}
	if err != nil {
		return ProbeResult{}, fmt.Errorf("[nmap-binary] run failed on %s: %w", hostPort, err)
	}

	for _, scannedHost := range result.Hosts {
		for _, portInfo := range scannedHost.Ports {
			if portInfo.State.State != "open" {
				continue
			}

			svc := portInfo.Service
			serviceName := strings.ToLower(strings.TrimSpace(svc.Name))
			product := strings.TrimSpace(svc.Product)
			version := strings.TrimSpace(svc.Version)
			extraInfo := strings.TrimSpace(svc.ExtraInfo)
			osType := strings.TrimSpace(svc.OSType)
			deviceType := strings.TrimSpace(svc.DeviceType)
			isTunnel := strings.EqualFold(strings.TrimSpace(svc.Tunnel), "ssl")

			proto, url := resolveProtoURL(serviceName, isTunnel, hostPort)
			tags := buildTags(serviceName, product, version, osType, deviceType, isTunnel, svc.CPEs)

			var rawResponse string
			for _, script := range portInfo.Scripts {
				if script.ID == "banner" {
					rawResponse = strings.TrimSpace(script.Output)
					break
				}
			}
			if rawResponse == "" {
				rawResponse = fmt.Sprintf(
					"service=%s product=%s version=%s osType=%s deviceType=%s extraInfo=%s cpes=%v confidence=%d",
					serviceName, product, version, osType, deviceType, extraInfo, svc.CPEs, svc.Confidence,
				)
			}

			cpeStrings := make([]string, 0, len(svc.CPEs))
			for _, cpe := range svc.CPEs {
				cpeStrings = append(cpeStrings, string(cpe))
			}

			logger.DAST("Nmap", "%s -> service=%s product=%s version=%s tags=%v", hostPort, serviceName, product, version, tags)

			return ProbeResult{
				URL:         url,
				Proto:       proto,
				Tags:        tags,
				RawResponse: rawResponse,
				Service:     serviceName,
				Product:     product,
				Version:     version,
				CPEs:        cpeStrings,
				Source:      "nmap",
			}, nil
		}
	}

	return ProbeResult{}, fmt.Errorf("[nmap-binary] no open service detected on %s", hostPort)
}

func ActiveProbe(ctx context.Context, host string, port int) (ProbeResult, error) {
	hostPort := fmt.Sprintf("%s:%d", host, port)
	logger.DAST("ActiveProbe", "starting featureless probe on %s", hostPort)

	tags := make(map[string]bool)
	var rawParts []string
	proto := "tcp"
	url := hostPort

	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if resp, err := doGet(probeCtx, client, "https://"+hostPort+"/"); err == nil {
		proto = "https"
		url = "https://" + hostPort
		tags["ssl"] = true
		tags["https"] = true
		tags["web"] = true
		extractHeaderTags(resp.Header, tags)
		tags[fmt.Sprintf("http-%d", resp.StatusCode)] = true
		rawParts = append(rawParts, fmt.Sprintf("HTTPS_GET status=%d server=%q", resp.StatusCode, resp.Header.Get("Server")))
		resp.Body.Close()
	} else if resp, err := doGet(probeCtx, client, "http://"+hostPort+"/"); err == nil {
		proto = "http"
		url = "http://" + hostPort
		tags["web"] = true
		tags["http"] = true
		extractHeaderTags(resp.Header, tags)
		tags[fmt.Sprintf("http-%d", resp.StatusCode)] = true
		rawParts = append(rawParts, fmt.Sprintf("HTTP_GET status=%d server=%q", resp.StatusCode, resp.Header.Get("Server")))
		resp.Body.Close()
	}

	if banner, err := rawHTTP10Request(probeCtx, hostPort); err == nil && banner != "" {
		rawParts = append(rawParts, "HTTP1.0_DOWNGRADE: "+banner[:min(len(banner), 256)])
		extractBannerTags(banner, tags)
	}

	if banner, err := malformedRequest(probeCtx, hostPort); err == nil && banner != "" {
		rawParts = append(rawParts, "MALFORMED_REQ: "+banner[:min(len(banner), 256)])
		extractBannerTags(banner, tags)
	}

	if certInfo, err := tlsCertProbe(probeCtx, hostPort); err == nil && certInfo != "" {
		rawParts = append(rawParts, "TLS_CERT: "+certInfo)
		tags["ssl"] = true
		for _, word := range strings.Fields(strings.ToLower(certInfo)) {
			if len(word) >= 3 && !strings.Contains(word, ".") {
				tags[word] = true
			}
		}
	}

	tagList := mapToSlice(tags)
	if len(tagList) == 0 {
		tagList = FallbackTags
		logger.DAST("ActiveProbe", "%s -> all probes failed, using fallback tags", hostPort)
	} else {
		logger.DAST("ActiveProbe", "%s -> extracted tags=%v", hostPort, tagList)
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

func doGet(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")
	return client.Do(req)
}

func rawHTTP10Request(ctx context.Context, hostPort string) (string, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", hostPort)
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

func malformedRequest(ctx context.Context, hostPort string) (string, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, _ = fmt.Fprintf(conn, "HELLO / HTTP/9.9\r\nHost: %s\r\n\r\n", hostPort)

	buf := make([]byte, 512)
	n, _ := io.ReadAtLeast(conn, buf, 1)
	if n == 0 {
		return "", fmt.Errorf("empty response")
	}
	return string(buf[:n]), nil
}

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

func extractHeaderTags(header http.Header, tags map[string]bool) {
	if server := header.Get("Server"); server != "" {
		for _, word := range strings.Fields(strings.ToLower(server)) {
			word = strings.Trim(word, "/.()")
			if len(word) >= 2 {
				tags[word] = true
			}
		}
	}

	if poweredBy := header.Get("X-Powered-By"); poweredBy != "" {
		for _, word := range strings.Fields(strings.ToLower(poweredBy)) {
			word = strings.Trim(word, "/.()")
			if len(word) >= 2 {
				tags[word] = true
			}
		}
	}

	for _, key := range []string{"X-Generator", "X-AspNet-Version", "X-Runtime", "Via"} {
		if value := header.Get(key); value != "" {
			tags[strings.ToLower(strings.Fields(value)[0])] = true
		}
	}

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
		for _, pattern := range patterns {
			if strings.Contains(lower, pattern) {
				tags[tag] = true
			}
		}
	}
}

func mapToSlice(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func normalizeTag(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, " ", "-")
	return name
}

func resolveProtoURL(serviceName string, isTunnel bool, hostPort string) (proto, url string) {
	if isTunnel || serviceName == "https" || strings.Contains(serviceName, "ssl") {
		return "https", "https://" + hostPort
	}
	if serviceName == "http" || strings.HasPrefix(serviceName, "http") {
		return "http", "http://" + hostPort
	}
	return "tcp", hostPort
}

func buildTags(serviceName, product, version, osType, deviceType string, isTunnel bool, cpes []nmap.CPE) []string {
	if serviceName == "" || serviceName == "unknown" {
		return FallbackTags
	}

	tagSet := make(map[string]bool)
	for _, cpe := range cpes {
		parts := strings.Split(string(cpe), ":")
		if len(parts) >= 4 {
			if productName := strings.ToLower(parts[3]); productName != "" && productName != "*" {
				tagSet[productName] = true
			}
		}
		if len(parts) >= 3 {
			if vendor := strings.ToLower(parts[2]); vendor != "" && vendor != "*" {
				tagSet[vendor] = true
			}
		}
	}

	if product != "" {
		for _, word := range strings.Fields(product) {
			if tag := normalizeTag(word); len(tag) >= 2 {
				tagSet[tag] = true
			}
		}
	}

	tagSet[serviceName] = true
	if version != "" {
		tagSet[version] = true
	}
	if osType != "" {
		tagSet[normalizeTag(osType)] = true
	}
	if deviceType != "" {
		tagSet[normalizeTag(deviceType)] = true
	}

	switch {
	case serviceName == "http" || strings.HasPrefix(serviceName, "http"):
		tagSet["web"] = true
	case isTunnel || serviceName == "https" || strings.Contains(serviceName, "ssl"):
		tagSet["http"] = true
		tagSet["ssl"] = true
		tagSet["web"] = true
	case serviceName == "ftp" || serviceName == "sftp":
		tagSet["network"] = true
	case serviceName == "mysql" || serviceName == "postgresql" || serviceName == "mssql" ||
		serviceName == "oracle-tns" || serviceName == "ms-sql-s":
		tagSet["database"] = true
	case serviceName == "redis" || serviceName == "memcached" || serviceName == "mongodb":
		tagSet["database"] = true
	case serviceName == "smtp" || serviceName == "imap" || serviceName == "pop3":
		tagSet["mail"] = true
	case serviceName == "rdp" || serviceName == "ms-wbt-server":
		tagSet["rdp"] = true
		tagSet["windows"] = true
	case serviceName == "ldap" || serviceName == "ldaps":
		tagSet["ldap"] = true
	case serviceName == "smb" || serviceName == "microsoft-ds" || serviceName == "netbios-ssn":
		tagSet["smb"] = true
		tagSet["windows"] = true
	}

	tags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	return tags
}
