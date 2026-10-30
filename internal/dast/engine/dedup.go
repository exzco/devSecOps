package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"devsecops/internal/dast/model"
)

var (
	ErrRequestBudgetExceeded  = errors.New("request budget exceeded")
	ErrDurationBudgetExceeded = errors.New("duration budget exceeded")
)

type Aggregator struct {
	mu           sync.Mutex
	findings     map[string]model.Finding
	observations map[string]model.PortObservation
	openPorts    int
}

func NewAggregator() *Aggregator {
	return &Aggregator{
		findings:     make(map[string]model.Finding),
		observations: make(map[string]model.PortObservation),
	}
}

func (a *Aggregator) IngestObservation(obs model.PortObservation) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := fmt.Sprintf("%s:%d", obs.Host, obs.Port)
	existing, exists := a.observations[key]
	if !exists {
		a.observations[key] = obs
		if obs.Status == "OPEN" {
			a.openPorts++
		}
	} else if existing.Status != "OPEN" && obs.Status == "OPEN" {
		a.observations[key] = obs
		a.openPorts++
	}
}

func (a *Aggregator) IngestFinding(f model.Finding) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if f.StableKey == "" {
		f.StableKey = model.GenerateStableFindingKey(f.MatchedAt, f.MatchedAt, f.CheckID, "", "")
	}

	existing, exists := a.findings[f.StableKey]
	if !exists {
		a.findings[f.StableKey] = f
	} else {
		if existing.Severity == model.SeverityInfo && f.Severity != model.SeverityInfo {
			a.findings[f.StableKey] = f
		}
	}
}

func (a *Aggregator) Findings() []model.Finding {
	a.mu.Lock()
	defer a.mu.Unlock()

	list := make([]model.Finding, 0, len(a.findings))
	for _, f := range a.findings {
		list = append(list, f)
	}
	return list
}

func (a *Aggregator) Observations() []model.PortObservation {
	a.mu.Lock()
	defer a.mu.Unlock()

	list := make([]model.PortObservation, 0, len(a.observations))
	for _, o := range a.observations {
		list = append(list, o)
	}
	return list
}

func (a *Aggregator) OpenPorts() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.openPorts
}

type RateLimiter struct {
	tokens chan struct{}
	stop   chan struct{}
}

func NewRateLimiter(maxRPS int) *RateLimiter {
	if maxRPS <= 0 {
		maxRPS = 50
	}

	rl := &RateLimiter{
		tokens: make(chan struct{}, maxRPS),
		stop:   make(chan struct{}),
	}

	for i := 0; i < maxRPS; i++ {
		rl.tokens <- struct{}{}
	}

	go func() {
		ticker := time.NewTicker(time.Second / time.Duration(maxRPS))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				select {
				case rl.tokens <- struct{}{}:
				default:
				}
			case <-rl.stop:
				return
			}
		}
	}()

	return rl
}

func (r *RateLimiter) Close() {
	close(r.stop)
}

func (r *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.tokens:
		return nil
	}
}

type BudgetTracker struct {
	policy   *model.Policy
	start    time.Time
	reqCount int64
	mu       sync.Mutex
}

func NewBudgetTracker(p *model.Policy) *BudgetTracker {
	if p == nil {
		p = model.DefaultPolicy()
	}
	return &BudgetTracker{
		policy: p,
		start:  time.Now(),
	}
}

func (b *BudgetTracker) CheckAndRecordRequest() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.policy.MaxDurationMinutes > 0 && time.Since(b.start) > time.Duration(b.policy.MaxDurationMinutes)*time.Minute {
		return ErrDurationBudgetExceeded
	}

	if b.policy.MaxRequestsTotal > 0 && b.reqCount >= b.policy.MaxRequestsTotal {
		return ErrRequestBudgetExceeded
	}

	b.reqCount++
	return nil
}
