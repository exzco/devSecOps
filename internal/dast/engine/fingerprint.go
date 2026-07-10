package engine

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	nmap "github.com/Ullaakut/nmap/v3"

	"devsecops/internal/dast/logger"
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
}

var FallbackTags = []string{"exposure", "misconfig", "config"}

var DefaultPortServices = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	110:   "pop3",
	143:   "imap",
	445:   "smb",
	873:   "rsync",
	1433:  "mssql",
	1521:  "oracle",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	6379:  "redis",
	9200:  "elasticsearch",
	11211: "memcached",
	27017: "mongodb",
}

// ProbeHttpFallback checks if the open port responds to standard HTTP/HTTPS GET requests.
func ProbeHttpFallback(ctx context.Context, host string, port int) (isHttp bool, isHttps bool) {
	hostPort := fmt.Sprintf("%s:%d", host, port)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 1. Try HTTPS
	reqHttps, err := http.NewRequestWithContext(ctx, "GET", "https://"+hostPort, nil)
	if err == nil {
		resp, err := client.Do(reqHttps)
		if err == nil {
			resp.Body.Close()
			return true, true
		}
	}

	// 2. Try HTTP
	reqHttp, err := http.NewRequestWithContext(ctx, "GET", "http://"+hostPort, nil)
	if err == nil {
		resp, err := client.Do(reqHttp)
		if err == nil {
			resp.Body.Close()
			return true, false
		}
	}

	return false, false
}


func normalizeTag(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, " ", "-")
	return name
}

func NmapProbe(ctx context.Context, host string, port int) (ProbeResult, error) {
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
		nmap.WithScripts("banner"), // 启用 banner 脚本获取端口 TCP socket 原始响应
	)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("[nmap-probe] create scanner failed: %w", err)
	}

	result, warnings, err := scanner.Run()
	if warnings != nil {
		for _, w := range *warnings {
			logger.Printf("[nmap-probe] warning on %s: %s\n", hostPort, w)
		}
	}
	if err != nil {
		return ProbeResult{}, fmt.Errorf("[nmap-probe] run failed on %s: %w", hostPort, err)
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

			// 优先读取 nmap -script=banner 的原始 TCP 套接字响应
			var rawResp string
			for _, script := range p.Scripts {
				if script.ID == "banner" {
					rawResp = strings.TrimSpace(script.Output)
					break
				}
			}

			// 如果没拿到原始 banner，则回退为格式化的指纹信息
			if rawResp == "" {
				rawResp = fmt.Sprintf(
					"service=%s product=%s version=%s osType=%s deviceType=%s extraInfo=%s cpes=%v confidence=%d",
					svcName, product, version, osType, deviceType, extraInfo, svc.CPEs, svc.Confidence,
				)
			}

			logger.Printf("[nmap-probe] %s → service=%s product=%s version=%s osType=%s cpes=%v tags=%v\n",
				hostPort, svcName, product, version, osType, svc.CPEs, tags)

			cpeStrings := []string{}
			for _, cpe := range svc.CPEs {
				cpeStrings = append(cpeStrings, string(cpe))
			}

			return ProbeResult{
				URL:         url,
				Proto:       proto,
				Tags:        tags,
				RawResponse: rawResp,
				Service:     svcName,
				Product:     product,
				Version:     version,
				CPEs:        cpeStrings,
			}, nil
		}
	}

	logger.Printf("[nmap-probe] %s → no service detected by nmap. Falling back to fingerprintx...\n", hostPort)
	fxResult, fxErr := FingerprintxProbe(ctx, host, port)
	if fxErr == nil && fxResult.Service != "" && fxResult.Service != "unknown" {
		logger.Printf("[nmap-probe] %s → fingerprintx fallback successfully identified: service=%s tags=%v\n", hostPort, fxResult.Service, fxResult.Tags)
		return fxResult, nil
	}

	logger.Printf("[nmap-probe] %s → both nmap and fingerprintx failed. Running custom fallback strategies...\n", hostPort)

	// A. Try HTTP/HTTPS probe fallback (P0)
	if isHttp, isHttps := ProbeHttpFallback(ctx, host, port); isHttp {
		proto := "http"
		url := "http://" + hostPort
		tags := []string{"web", "http"}
		if isHttps {
			proto = "https"
			url = "https://" + hostPort
			tags = append(tags, "ssl", "https")
		}
		logger.Printf("[nmap-probe] %s → fallback resolved via HTTP Probe: proto=%s tags=%v\n", hostPort, proto, tags)
		return ProbeResult{
			URL:         url,
			Proto:       proto,
			Tags:        tags,
			RawResponse: fmt.Sprintf("fallback_http_probe: is_https=%v", isHttps),
			Service:     proto,
		}, nil
	}

	// B. Try Port-to-Service heuristic mapping (P1)
	if svcName, ok := DefaultPortServices[port]; ok {
		logger.Printf("[nmap-probe] %s → fallback resolved via Port-to-Service heuristic mapping: service=%s\n", hostPort, svcName)
		tags := []string{svcName}
		if svcName == "mysql" || svcName == "redis" || svcName == "postgresql" || svcName == "mongodb" {
			tags = append(tags, "database")
		}
		return ProbeResult{
			URL:         hostPort,
			Proto:       "tcp",
			Tags:        tags,
			RawResponse: fmt.Sprintf("fallback_port_mapping: inferred=%s", svcName),
			Service:     svcName,
		}, nil
	}

	// C. Generic TCP fallback (P2)
	logger.Printf("[nmap-probe] %s → fallback resolved via Generic TCP fallback\n", hostPort)
	return ProbeResult{
		URL:         hostPort,
		Proto:       "tcp",
		Tags:        []string{"network", "general-tcp"},
		RawResponse: "nmap: no service detected; fingerprintx: " + fmt.Sprintf("%v", fxErr) + "; fallback: generic tcp",
		Service:     "unknown",
	}, nil
}

type FingerprintxOutput struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	TLS       bool   `json:"tls"`
	Transport string `json:"transport"`
}

// FingerprintxProbe 调用 fingerprintx 进行外部探测，解析其 JSON 响应并转化为统一结构
func FingerprintxProbe(ctx context.Context, host string, port int) (ProbeResult, error) {
	hostPort := fmt.Sprintf("%s:%d", host, port)

	if _, err := exec.LookPath("fingerprintx"); err != nil {
		return ProbeResult{}, fmt.Errorf("fingerprintx binary not found in PATH")
	}

	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(probeCtx, "fingerprintx", "-target", hostPort, "--json")
	out, err := cmd.Output()
	if err != nil {
		return ProbeResult{}, fmt.Errorf("run fingerprintx failed: %w", err)
	}

	var fxOut FingerprintxOutput
	lines := strings.Split(string(out), "\n")
	parsed := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		if err := json.Unmarshal([]byte(line), &fxOut); err == nil {
			parsed = true
			break
		}
	}

	if !parsed || fxOut.Protocol == "" {
		return ProbeResult{}, fmt.Errorf("no service identified by fingerprintx")
	}

	svcName := strings.ToLower(fxOut.Protocol)
	isTunnel := fxOut.TLS
	proto, url := resolveProtoURL(svcName, isTunnel, hostPort)

	// 组装 tags 列表
	tags := []string{svcName, "web"}
	if isTunnel {
		tags = append(tags, "ssl", "https")
	} else if svcName == "http" {
		tags = append(tags, "http")
	}

	return ProbeResult{
		URL:         url,
		Proto:       proto,
		Tags:        tags,
		RawResponse: fmt.Sprintf("fingerprintx: service=%s tls=%v transport=%s", svcName, isTunnel, fxOut.Transport),
		Service:     svcName,
	}, nil
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

// buildTags 从 nmap 的所有服务信息中提取尽可能精准的 tag 集合。
// 优先级: CPE > product > svcName > OSType/DeviceType
func buildTags(svcName, product, version, osType, deviceType string, isTunnel bool, cpes []nmap.CPE) []string {
	if svcName == "" || svcName == "unknown" {
		return FallbackTags
	}

	tagSet := make(map[string]bool)

	// 1. 从 CPE 解析产品名（最精准）
	// CPE 格式: cpe:/a:vendor:product:version 或 cpe:/o:vendor:os:version
	for _, cpe := range cpes {
		parts := strings.Split(string(cpe), ":")
		// parts[0]="cpe", [1]="/a", [2]=vendor, [3]=product, [4]=version
		if len(parts) >= 4 {
			cpeProduct := strings.ToLower(parts[3])
			if cpeProduct != "" && cpeProduct != "*" {
				tagSet[cpeProduct] = true
			}
		}
		if len(parts) >= 3 {
			cpeVendor := strings.ToLower(parts[2])
			if cpeVendor != "" && cpeVendor != "*" {
				tagSet[cpeVendor] = true
			}
		}
	}

	// 2. product 字段拆词（"Apache httpd" → "apache"、"httpd"）
	if product != "" {
		for _, word := range strings.Fields(product) {
			tag := normalizeTag(word)
			if len(tag) >= 2 {
				tagSet[tag] = true
			}
		}
	}

	// 3. svcName 本身
	tagSet[svcName] = true

	// 4. 版本号（部分 nuclei 模板按版本过滤）
	if version != "" {
		tagSet[version] = true
	}

	// 5. OSType（如 "Windows", "Linux"）
	if osType != "" {
		tagSet[normalizeTag(osType)] = true
	}

	// 6. DeviceType（如 "router", "printer", "webcam"）
	if deviceType != "" {
		tagSet[normalizeTag(deviceType)] = true
	}

	// 7. 协议族补充 tag（与原逻辑保持兼容）
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
