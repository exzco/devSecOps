package engine

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"devsecops/internal/model"
)

type ScanOptions struct {
	Targets      []string      `json:"targets"`
	PortOverride string        `json:"port_override,omitempty"`
	Policy       *model.Policy `json:"policy,omitempty"`
}

type ScanResult struct {
	ScanRunID    string                  `json:"scan_run_id"`
	StartedAt    time.Time               `json:"started_at"`
	CompletedAt  time.Time               `json:"completed_at"`
	Targets      []model.Target          `json:"targets"`
	Observations []model.PortObservation `json:"observations"`
	Services     []model.Service         `json:"services"`
	Findings     []model.Finding         `json:"findings"`
	OpenPorts    int                     `json:"open_ports"`
	Endpoints    int                     `json:"endpoints"`
	DurationMs   int64                   `json:"duration_ms"`
}

type Runner struct {
	httpClient  *FingerprintHTTPClient
	tlsAnalyzer *TLSAnalyzer
	ruleIndex   *RuleIndex
	fpEngine    *FingerprintEngine
}

func NewRunner(pocDir string) *Runner {
	return &Runner{
		httpClient:  NewFingerprintHTTPClient(10 * time.Second),
		tlsAnalyzer: NewTLSAnalyzer(800 * time.Millisecond),
		ruleIndex:   NewRuleIndex(pocDir, DefaultPOCIndexFile),
		fpEngine:    NewFingerprintEngine(),
	}
}

func (r *Runner) Run(ctx context.Context, opts ScanOptions) (*ScanResult, error) {
	start := time.Now()
	scanRunID := model.NewUUID()
	policy := opts.Policy
	if policy == nil {
		policy = model.DefaultPolicy()
	}

	var targets []model.Target
	for _, raw := range opts.Targets {
		target := model.ParseTarget(raw)
		if target.IsValid {
			targets = append(targets, *target)
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets to scan")
	}

	rateLimiter := NewRateLimiter(policy.MaxRPS)
	defer rateLimiter.Close()
	budget := NewBudgetTracker(policy)
	aggregator := NewAggregator()

	for _, target := range targets {
		if err := rateLimiter.Wait(ctx); err != nil {
			return nil, err
		}
		if err := budget.CheckAndRecordRequest(); err != nil {
			return nil, err
		}
		portRange := opts.PortOverride
		if portRange == "" && target.Port > 0 {
			portRange = fmt.Sprintf("%d", target.Port)
		}
		if portRange == "" {
			portRange = policy.PortProfile
		}
		observations, err := ScanPorts(ctx, target.Host, portRange, policy)
		if err != nil {
			continue
		}
		for _, observation := range observations {
			aggregator.IngestObservation(observation)
		}
	}

	services, endpointsFound := r.identifyServices(ctx, targets, aggregator.Observations())
	var findings []model.Finding
	for _, service := range services {
		if service.Protocol == "" || service.Protocol == "unknown" {
			continue
		}
		targetURL := fmt.Sprintf("%s://%s:%d", service.Protocol, service.Host, service.Port)
		serviceFindings, err := ExecuteChecks(
			ctx,
			r.ruleIndex.SelectChecks(policy),
			scanRunID,
			targetURL,
		)
		if err != nil {
			continue
		}
		for _, finding := range serviceFindings {
			aggregator.IngestFinding(finding)
		}
	}
	findings = aggregator.Findings()

	completed := time.Now()
	return &ScanResult{
		ScanRunID:    scanRunID,
		StartedAt:    start,
		CompletedAt:  completed,
		Targets:      targets,
		Observations: aggregator.Observations(),
		Services:     services,
		Findings:     findings,
		OpenPorts:    aggregator.OpenPorts(),
		Endpoints:    endpointsFound,
		DurationMs:   completed.Sub(start).Milliseconds(),
	}, nil
}

func (r *Runner) identifyServices(
	ctx context.Context,
	targets []model.Target,
	observations []model.PortObservation,
) ([]model.Service, int) {
	type candidate struct {
		target model.Target
		port   int
	}
	var candidates []candidate
	for _, observation := range observations {
		if observation.Status != "OPEN" {
			continue
		}
		for _, target := range targets {
			if strings.EqualFold(target.Host, observation.Host) {
				candidates = append(candidates, candidate{target: target, port: observation.Port})
				break
			}
		}
	}

	var services []model.Service
	endpointsFound := 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	for _, item := range candidates {
		wg.Add(1)
		go func(item candidate) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			protocol := "http"
			if item.port == 443 || item.port == 8443 {
				protocol = "https"
			}
			tlsInfo, err := r.tlsAnalyzer.AnalyzeTLS(ctx, item.target.Host, item.port)
			if err == nil && tlsInfo != nil {
				protocol = "https"
			}

			targetURL := fmt.Sprintf("%s://%s:%d", protocol, item.target.Host, item.port)
			response, err := r.httpClient.Do(ctx, "GET", targetURL, nil, "")
			service := model.Service{
				Host:       item.target.Host,
				Port:       item.port,
				Transport:  "tcp",
				Protocol:   protocol,
				TLS:        tlsInfo,
				ObservedAt: model.NowUTC(),
			}

			rawDetails := map[string]any{
				"target_url": targetURL,
				"transport":  "tcp",
				"protocol":   protocol,
			}
			if tlsInfo != nil {
				rawDetails["tls"] = tlsInfo
			}

			endpointCount := 0
			if err == nil && response != nil {
				endpointCount++
				service.Product = r.fpEngine.DetectWebTechnologies(response)
				service.Headers = response.Headers
				if serverHeader, ok := response.Headers["server"]; ok && serverHeader != "" {
					service.Banner = serverHeader
				}
				rawDetails["status_code"] = response.StatusCode
				rawDetails["headers"] = response.Headers
				rawDetails["duration_ms"] = response.DurationMs
				if service.Product != "" {
					rawDetails["detected_tech"] = service.Product
				}
				if service.Banner != "" {
					rawDetails["server_banner"] = service.Banner
				}
				if parsedURL, parseErr := url.Parse(targetURL); parseErr == nil {
					endpoints := ExtractEndpointsFromHTML(parsedURL, response.Body)
					endpointCount += len(endpoints)
					if len(endpoints) > 0 {
						rawDetails["endpoints"] = endpoints
					}
				}
			} else if err != nil {
				rawDetails["probe_error"] = err.Error()
			}
			service.RawDetails = rawDetails

			mu.Lock()
			services = append(services, service)
			endpointsFound += endpointCount
			mu.Unlock()
		}(item)
	}
	wg.Wait()
	return services, endpointsFound
}
