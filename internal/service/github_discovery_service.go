package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"gorm.io/gorm"

	"devsecops/internal/model"
)

const githubSearchAPI = "https://api.github.com/search/repositories"

type GitHubDiscoveryService struct {
	httpClient *http.Client
	repoSvc    *RepoService
	scanSvc    *ScanService
}

type DiscoveryResult struct {
	Imported []*model.Repository `json:"imported"`
	Skipped  []string            `json:"skipped"`
}

func NewGitHubDiscoveryService(repoSvc *RepoService, scanSvc *ScanService) *GitHubDiscoveryService {
	return &GitHubDiscoveryService{
		httpClient: &http.Client{Timeout: 25 * time.Second},
		repoSvc:    repoSvc,
		scanSvc:    scanSvc,
	}
}

func (s *GitHubDiscoveryService) DiscoverAndCreate(ctx context.Context, req *model.DiscoverGithubReposRequest) (*DiscoveryResult, error) {
	items, err := s.searchRepositories(ctx, req.Language, req.MinStars, req.MaxStars, req.Limit)
	if err != nil {
		return nil, err
	}

	result := &DiscoveryResult{
		Imported: make([]*model.Repository, 0, len(items)),
		Skipped:  make([]string, 0),
	}

	for _, item := range items {
		if req.MaxStars > 0 && item.StargazersCount > req.MaxStars {
			result.Skipped = append(result.Skipped, item.CloneURL+" (exceed max_stars)")
			continue
		}

		if _, err := s.repoSvc.GetByURL(item.CloneURL); err == nil {
			result.Skipped = append(result.Skipped, item.CloneURL+" (already exists)")
			continue
		} else if err != nil && err != gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("check repo exists failed: %w", err)
		}

		branch := strings.TrimSpace(req.Branch)
		if branch == "" {
			branch = strings.TrimSpace(item.DefaultBranch)
		}
		if branch == "" {
			branch = "main"
		}

		createReq := &model.CreateRepoRequest{
			Name:            item.FullName,
			URL:             item.CloneURL,
			Branch:          branch,
			Language:        normalizeLanguage(req.Language),
			Stars:           item.StargazersCount,
			Source:          "github_discovery",
			AutoScanEnabled: false,
			AuthType:        "none",
		}

		repo, err := s.repoSvc.Create(createReq)
		if err != nil {
			result.Skipped = append(result.Skipped, item.CloneURL+" (create failed: "+err.Error()+")")
			continue
		}

		_, err = s.scanSvc.CreateTask(repo.ID, model.TriggerTypeManual, repo.Branch, repo.Language, req.QuerySuite, req.RuleProfile, "")
		if err != nil {
			result.Skipped = append(result.Skipped, item.CloneURL+" (task create failed: "+err.Error()+")")
			continue
		}

		result.Imported = append(result.Imported, repo)
	}

	return result, nil
}

func (s *GitHubDiscoveryService) searchRepositories(ctx context.Context, language string, minStars, maxStars, limit int) ([]model.GithubSearchItem, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if minStars <= 0 {
		minStars = 1000
	}
	if maxStars > 0 && maxStars < minStars {
		return nil, fmt.Errorf("max_stars must be greater than or equal to min_stars")
	}

	starsRange := fmt.Sprintf(">=%d", minStars)
	if maxStars > 0 {
		starsRange = fmt.Sprintf("%d..%d", minStars, maxStars)
	}
	query := fmt.Sprintf("language:%s stars:%s", normalizeLanguage(language), starsRange)
	u, err := url.Parse(githubSearchAPI)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("q", query)
	q.Set("sort", "stars")
	q.Set("order", "desc")
	q.Set("per_page", fmt.Sprintf("%d", limit))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "codeql-scanner-platform")
	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("github search failed status=%d body=%s", resp.StatusCode, string(body))
	}

	var payload model.GithubSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	return payload.Items, nil
}

func normalizeLanguage(lang string) string {
	v := strings.ToLower(strings.TrimSpace(lang))
	switch v {
	case "js":
		return "javascript"
	case "golang":
		return "go"
	default:
		return v
	}
}
