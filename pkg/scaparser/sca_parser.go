package scaparser

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"devsecops/pkg/cvefetcher"
)

// DependencyInfo holds dependency metadata for SCA
type DependencyInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"` // Go, npm, PyPI, Maven
	Direct    bool   `json:"direct"`
}

// ScaResult holds parsed dependencies and detected vulnerabilities
type ScaResult struct {
	Dependencies    []DependencyInfo            `json:"dependencies"`
	Vulnerabilities []cvefetcher.OSVVulnerability `json:"vulnerabilities"`
}

type GenericSCAParser struct {
	fetcher *cvefetcher.CVEFetcher
}

func NewGenericSCAParser() *GenericSCAParser {
	return &GenericSCAParser{
		fetcher: cvefetcher.NewCVEFetcher(0),
	}
}

// ParseProjectDependencies automatically scans directory for go.mod, package.json, requirements.txt
func (p *GenericSCAParser) ParseProjectDependencies(dirPath string) ([]DependencyInfo, error) {
	var deps []DependencyInfo

	// 1. Check go.mod
	goModPath := filepath.Join(dirPath, "go.mod")
	if _, err := os.Stat(goModPath); err == nil {
		goDeps, err := parseGoMod(goModPath)
		if err == nil {
			deps = append(deps, goDeps...)
		}
	}

	// 2. Check package.json
	pkgJsonPath := filepath.Join(dirPath, "package.json")
	if _, err := os.Stat(pkgJsonPath); err == nil {
		npmDeps, err := parsePackageJson(pkgJsonPath)
		if err == nil {
			deps = append(deps, npmDeps...)
		}
	}

	// 3. Check requirements.txt
	reqPath := filepath.Join(dirPath, "requirements.txt")
	if _, err := os.Stat(reqPath); err == nil {
		pypiDeps, err := parseRequirementsTxt(reqPath)
		if err == nil {
			deps = append(deps, pypiDeps...)
		}
	}

	return deps, nil
}

// ScanVulnerabilities parses project dependencies and queries OSV database
func (p *GenericSCAParser) ScanVulnerabilities(ctx context.Context, dirPath string) (*ScaResult, error) {
	deps, err := p.ParseProjectDependencies(dirPath)
	if err != nil {
		return nil, fmt.Errorf("parse dependencies: %w", err)
	}

	var allVulns []cvefetcher.OSVVulnerability
	for _, dep := range deps {
		vulns, err := p.fetcher.FetchOSVForPackage(ctx, dep.Ecosystem, dep.Name, dep.Version)
		if err == nil && len(vulns) > 0 {
			allVulns = append(allVulns, vulns...)
		}
	}

	return &ScaResult{
		Dependencies:    deps,
		Vulnerabilities: allVulns,
	}, nil
}

func parseGoMod(filePath string) ([]DependencyInfo, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []DependencyInfo
	scanner := bufio.NewScanner(file)
	inRequire := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "require (" {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		if strings.HasPrefix(line, "require ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				deps = append(deps, DependencyInfo{
					Name:      parts[1],
					Version:   parts[2],
					Ecosystem: "Go",
					Direct:    !strings.Contains(line, "// indirect"),
				})
			}
		} else if inRequire && line != "" && !strings.HasPrefix(line, "//") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				deps = append(deps, DependencyInfo{
					Name:      parts[0],
					Version:   parts[1],
					Ecosystem: "Go",
					Direct:    !strings.Contains(line, "// indirect"),
				})
			}
		}
	}

	return deps, nil
}

func parsePackageJson(filePath string) ([]DependencyInfo, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	var deps []DependencyInfo
	for name, ver := range pkg.Dependencies {
		deps = append(deps, DependencyInfo{
			Name:      name,
			Version:   cleanVersion(ver),
			Ecosystem: "npm",
			Direct:    true,
		})
	}
	for name, ver := range pkg.DevDependencies {
		deps = append(deps, DependencyInfo{
			Name:      name,
			Version:   cleanVersion(ver),
			Ecosystem: "npm",
			Direct:    false,
		})
	}

	return deps, nil
}

func parseRequirementsTxt(filePath string) ([]DependencyInfo, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []DependencyInfo
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "==")
		if len(parts) == 2 {
			deps = append(deps, DependencyInfo{
				Name:      strings.TrimSpace(parts[0]),
				Version:   strings.TrimSpace(parts[1]),
				Ecosystem: "PyPI",
				Direct:    true,
			})
		}
	}

	return deps, nil
}

func cleanVersion(v string) string {
	v = strings.TrimPrefix(v, "^")
	v = strings.TrimPrefix(v, "~")
	v = strings.TrimPrefix(v, ">=")
	return strings.TrimSpace(v)
}
