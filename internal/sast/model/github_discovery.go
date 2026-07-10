package model

// DiscoverGithubReposRequest requests importing popular GitHub repositories and enqueuing scans.
type DiscoverGithubReposRequest struct {
	Language    string `json:"language" binding:"required,oneof=go java javascript python"`
	MinStars    int    `json:"min_stars"`
	MaxStars    int    `json:"max_stars"`
	Limit       int    `json:"limit"`
	Branch      string `json:"branch"`
	RuleProfile string `json:"rule_profile"`
	QuerySuite  string `json:"query_suite"`
}

// GithubSearchItem mirrors a subset of GitHub search repository result fields.
type GithubSearchItem struct {
	Name            string `json:"name"`
	FullName        string `json:"full_name"`
	HTMLURL         string `json:"html_url"`
	CloneURL        string `json:"clone_url"`
	DefaultBranch   string `json:"default_branch"`
	StargazersCount int    `json:"stargazers_count"`
	Language        string `json:"language"`
}

// GithubSearchResponse mirrors the GitHub Search API response shape.
type GithubSearchResponse struct {
	TotalCount int                `json:"total_count"`
	Items      []GithubSearchItem `json:"items"`
}
