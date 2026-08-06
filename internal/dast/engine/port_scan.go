package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	nmap "github.com/Ullaakut/nmap/v3"

	"devsecops/internal/config"
	"devsecops/pkg/logger"
)

func ScanIP(ctx context.Context, ip, portRange string, scanCfg config.DastConfig) ([]int, error) {
	ip = strings.TrimSpace(ip)
	logger.DAST("PortScan", "nmap scanning ip=%s ports=%s type=%s", ip, portRange, scanCfg.PortScanType)

	timeoutDuration := time.Duration(scanCfg.PortScanTimeout) * time.Second
	scanTimeout := timeoutDuration * time.Duration(scanCfg.PortScanThreads)
	if scanTimeout < 30*time.Second {
		scanTimeout = 30 * time.Second
	}
	if scanTimeout > 10*time.Minute {
		scanTimeout = 10 * time.Minute
	}

	scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	opts := []nmap.Option{
		nmap.WithTargets(ip),
		nmap.WithSkipHostDiscovery(),
		nmap.WithDisabledDNSResolution(),
	}

	switch portRange {
	case "", "top1000":
		opts = append(opts, nmap.WithMostCommonPorts(1000))
	case "full":
		opts = append(opts, nmap.WithPorts("1-65535"))
	default:
		opts = append(opts, nmap.WithPorts(portRange))
	}

	if scanCfg.PortScanType == "syn" {
		opts = append(opts, nmap.WithSYNScan())
	} else {
		opts = append(opts, nmap.WithConnectScan())
	}

	if scanCfg.PortScanRate > 0 {
		opts = append(opts, nmap.WithMinRate(scanCfg.PortScanRate))
	}

	scanner, err := nmap.NewScanner(scanCtx, opts...)
	if err != nil {
		return nil, fmt.Errorf("[portscan] create nmap scanner failed: %w", err)
	}

	result, warnings, err := scanner.Run()
	if warnings != nil {
		for _, warning := range *warnings {
			logger.DAST("PortScan", "nmap warning: %s", warning)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("[portscan] nmap run failed ip=%s: %w", ip, err)
	}

	var openPorts []int
	for _, host := range result.Hosts {
		for _, port := range host.Ports {
			if port.State.State == "open" {
				openPorts = append(openPorts, int(port.ID))
			}
		}
	}

	logger.DAST("PortScan", "nmap ip=%s found %d open ports", ip, len(openPorts))
	return openPorts, nil
}
