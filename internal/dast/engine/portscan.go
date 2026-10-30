package engine

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"devsecops/internal/dast/model"
)

var CommonTop100Ports = []int{
	21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 123, 135, 137, 139, 143, 161, 389,
	443, 445, 465, 500, 514, 587, 636, 873, 993, 995, 1025, 1080, 1099, 1433, 1521,
	2049, 2181, 2375, 2376, 2379, 3000, 3128, 3306, 3389, 4369, 5000, 5432, 5672,
	5900, 5984, 6379, 6443, 7001, 7077, 7890, 8000, 8008, 8080, 8081, 8082, 8083,
	8084, 8085, 8088, 8443, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 9418, 9999,
	10000, 11211, 15672, 27017, 27018, 28017, 33060, 50000, 50070,
}

func ScanPorts(ctx context.Context, host, portRange string, policy *model.Policy) ([]model.PortObservation, error) {
	start := time.Now()
	ports := ParsePortRange(portRange)
	timeout := 400 * time.Millisecond
	if policy != nil && policy.PortTimeoutSec > 0 {
		timeout = time.Duration(policy.PortTimeoutSec) * time.Second
	}
	openPorts, err := NativeGoScan(ctx, host, ports, 150, timeout)
	duration := time.Since(start).Milliseconds()

	if err != nil {
		return nil, err
	}

	observations := make([]model.PortObservation, 0, len(openPorts))
	for _, p := range openPorts {
		observations = append(observations, model.PortObservation{
			Host:        strings.ToLower(host),
			Port:        p,
			Transport:   "tcp",
			Status:      "OPEN",
			DurationMs:  duration,
			ProbeSource: "native_tcp",
			ObservedAt:  time.Now().UTC(),
		})
	}
	return observations, nil
}

func NativeGoScan(ctx context.Context, host string, ports []int, concurrency int, timeout time.Duration) ([]int, error) {
	if concurrency <= 0 {
		concurrency = 100
	}
	if timeout <= 0 {
		timeout = 400 * time.Millisecond
	}

	portsChan := make(chan int, len(ports))
	resultsChan := make(chan int, len(ports))
	var wg sync.WaitGroup

	dialer := NewDialer(timeout)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range portsChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				addr := net.JoinHostPort(host, strconv.Itoa(p))
				conn, err := dialer.DialContext(ctx, "tcp", addr)
				if err == nil {
					_ = conn.Close()
					resultsChan <- p
				}
			}
		}()
	}

	for _, p := range ports {
		portsChan <- p
	}
	close(portsChan)

	wg.Wait()
	close(resultsChan)

	var openPorts []int
	for p := range resultsChan {
		openPorts = append(openPorts, p)
	}
	sort.Ints(openPorts)
	return openPorts, nil
}

func ParsePortRange(portRange string) []int {
	portRange = strings.TrimSpace(portRange)
	if portRange == "" || portRange == "top100" {
		return CommonTop100Ports
	}

	portSet := make(map[int]struct{})

	if portRange == "top1000" {
		for _, p := range CommonTop100Ports {
			portSet[p] = struct{}{}
		}
		for p := 1; p <= 1024; p++ {
			portSet[p] = struct{}{}
		}
	} else {
		for _, part := range strings.Split(portRange, ",") {
			bounds := strings.Split(strings.TrimSpace(part), "-")
			if len(bounds) == 1 {
				if p, err := strconv.Atoi(bounds[0]); err == nil && p > 0 && p <= 65535 {
					portSet[p] = struct{}{}
				}
				continue
			}
			if len(bounds) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
				if err1 == nil && err2 == nil && start > 0 && start <= end && end <= 65535 {
					for p := start; p <= end; p++ {
						portSet[p] = struct{}{}
					}
				}
			}
		}
	}

	if len(portSet) == 0 {
		return CommonTop100Ports
	}

	result := make([]int, 0, len(portSet))
	for p := range portSet {
		result = append(result, p)
	}

	sort.Ints(result)
	return result
}
