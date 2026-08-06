package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"devsecops/pkg/logger"
)

var webPorts = map[int]bool{
	80: true, 443: true, 8080: true, 8443: true,
	3000: true, 4443: true, 5000: true, 7070: true,
	8000: true, 8008: true, 8081: true, 8088: true,
	8090: true, 8181: true, 8888: true,
	9000: true, 9080: true, 9090: true, 9200: true,
	9443: true, 10000: true, 10443: true,
}

var binaryBannerPatterns = []string{
	"ssh-", "220 ", "+ok ",
	"* ok ", "* bye",
	"220-",
	"redis", "redisd",
	"mysql", "mariadb",
	"postgres",
	"rdp", "\x03\x00",
	"smb", "\xffsmb",
}

func SniffAndRoute(ctx context.Context, host string, port int) (isWeb bool, isTLS bool) {
	hostPort := fmt.Sprintf("%s:%d", host, port)

	if webPorts[port] {
		isTLS = probeIsTLS(ctx, hostPort)
		logger.DAST("Sniff", "%s -> web port whitelist hit, isTLS=%v", hostPort, isTLS)
		return true, isTLS
	}

	if probeIsTLS(ctx, hostPort) {
		logger.DAST("Sniff", "%s -> TLS handshake succeeded", hostPort)
		return true, true
	}

	if banner := readTCPBanner(ctx, hostPort, 512); banner != "" {
		bannerLower := strings.ToLower(banner)
		if strings.HasPrefix(bannerLower, "http/") ||
			strings.Contains(bannerLower, "content-type:") ||
			strings.Contains(bannerLower, "server:") {
			logger.DAST("Sniff", "%s -> HTTP banner detected", hostPort)
			return true, false
		}

		for _, pattern := range binaryBannerPatterns {
			if strings.Contains(bannerLower, pattern) {
				logger.DAST("Sniff", "%s -> binary banner %s detected", hostPort, pattern)
				return false, false
			}
		}
	}

	logger.DAST("Sniff", "%s -> default binary flow", hostPort)
	return false, false
}

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

func readTCPBanner(ctx context.Context, hostPort string, n int) string {
	dialCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	dialer := net.Dialer{Timeout: 4 * time.Second}
	conn, err := dialer.DialContext(dialCtx, "tcp", hostPort)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	buf := make([]byte, n)
	readN, err := io.ReadAtLeast(conn, buf, 1)
	if err != nil || readN == 0 {
		return ""
	}
	return string(buf[:readN])
}
