package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"devsecops/internal/dast/logger"
)

// webPorts 是已知 Web 服务端口白名单，命中则直接路由到 Web 流
var webPorts = map[int]bool{
	80: true, 443: true, 8080: true, 8443: true,
	3000: true, 4443: true, 5000: true, 7070: true,
	8000: true, 8008: true, 8081: true, 8088: true,
	8090: true, 8181: true, 8888: true,
	9000: true, 9080: true, 9090: true, 9200: true,
	9443: true, 10000: true, 10443: true,
}

// SniffAndRoute 通过协议嗅探对端口进行流量分流判断。
// 返回 isWeb=true 时应走 Web 指纹路径；false 时走 Nmap 二进制服务探测路径。
// isTLS 指示该端口是否运行在 TLS 之上。
func SniffAndRoute(ctx context.Context, host string, port int) (isWeb bool, isTLS bool) {
	hostPort := fmt.Sprintf("%s:%d", host, port)

	// ── 规则 1: 端口白名单命中 ───────────────────────────────────────────
	if webPorts[port] {
		// 仍需确认 TLS
		isTLS = probeIsTLS(ctx, hostPort)
		logger.Printf("[sniff] %s → WebPort whitelist hit, isTLS=%v\n", hostPort, isTLS)
		return true, isTLS
	}

	// ── 规则 2: TLS 握手探测 ─────────────────────────────────────────────
	if probeIsTLS(ctx, hostPort) {
		logger.Printf("[sniff] %s → TLS handshake succeeded → Web/TLS flow\n", hostPort)
		return true, true
	}

	// ── 规则 3: TCP Banner 中含 HTTP 特征 ────────────────────────────────
	if banner := readTCPBanner(ctx, hostPort, 512); banner != "" {
		bannerLower := strings.ToLower(banner)
		if strings.HasPrefix(bannerLower, "http/") ||
			strings.Contains(bannerLower, "content-type:") ||
			strings.Contains(bannerLower, "server:") {
			logger.Printf("[sniff] %s → HTTP banner detected → Web flow\n", hostPort)
			return true, false
		}
		// Banner 含已知二进制协议特征
		for _, binaryPattern := range binaryBannerPatterns {
			if strings.Contains(bannerLower, binaryPattern) {
				logger.Printf("[sniff] %s → binary banner [%s] detected → Binary flow\n", hostPort, binaryPattern)
				return false, false
			}
		}
	}

	// ── 规则 4: 默认二进制服务流 ─────────────────────────────────────────
	logger.Printf("[sniff] %s → no Web signal → Binary flow\n", hostPort)
	return false, false
}

// binaryBannerPatterns 是已知二进制协议的 banner 特征片段
var binaryBannerPatterns = []string{
	"ssh-", "220 ", "+ok ", // ssh / ftp / pop3
	"* ok ", "* bye", // imap
	"220-",            // smtp
	"redis", "redisd", // redis
	"mysql", "mariadb", // mysql
	"postgres",        // pg
	"rdp", "\x03\x00", // rdp 前导字节
	"smb", "\xffsmb", // smb
}

// probeIsTLS 尝试 TLS 握手，成功返回 true
func probeIsTLS(ctx context.Context, hostPort string) bool {
	dialCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 4 * time.Second},
		Config:    &tls.Config{InsecureSkipVerify: true},
	}
	conn, err := dialer.DialContext(dialCtx, "tcp", hostPort)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// readTCPBanner 建立 TCP 连接并读取前 n 字节的 banner 数据
func readTCPBanner(ctx context.Context, hostPort string, n int) string {
	dialCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	d := net.Dialer{Timeout: 4 * time.Second}
	conn, err := d.DialContext(dialCtx, "tcp", hostPort)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	buf := make([]byte, n)
	nr, err := io.ReadAtLeast(conn, buf, 1)
	if err != nil || nr == 0 {
		return ""
	}
	return string(buf[:nr])
}
