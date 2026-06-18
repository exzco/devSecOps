package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	nmap "github.com/Ullaakut/nmap/v3"

	"devsecops/internal/config"
	"devsecops/internal/dast/logger"
)

func ScanIP(ctx context.Context, ip string, portRange string, scanCfg config.DastConfig) ([]int, error) {
	ip = strings.TrimSpace(ip)
	logger.Printf("[portscan] nmap scanning ip=%s ports=%s type=%s\n", ip, portRange, scanCfg.PortScanType)

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
	case "top1000", "":
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
		for _, w := range *warnings {
			logger.Printf("[portscan] nmap warning: %s\n", w)
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

	logger.Printf("[portscan] nmap ip=%s found %d open ports\n", ip, len(openPorts))
	return openPorts, nil
}
