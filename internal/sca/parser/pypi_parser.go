package parser

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// PyPiParser parses Python requirements.txt, pyproject.toml, and Pipfile
type PyPiParser struct{}

func (p *PyPiParser) Ecosystem() string {
	return "PyPI"
}

func (p *PyPiParser) CanParse(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "requirements.txt")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "pyproject.toml")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "Pipfile.lock")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "Pipfile")); err == nil {
		return true
	}
	return false
}

var reqRegex = regexp.MustCompile(`^([a-zA-Z0-9_\-\.]+)\s*([=><~=!]*)\s*([a-zA-Z0-9_\-\.]+)?`)

func (p *PyPiParser) Parse(dir string) ([]ParsedDependency, error) {
	var allDeps []ParsedDependency
	seen := make(map[string]bool)

	// 1. requirements.txt
	reqPath := filepath.Join(dir, "requirements.txt")
	if file, err := os.Open(reqPath); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
				continue
			}
			if idx := strings.Index(line, "#"); idx != -1 {
				line = strings.TrimSpace(line[:idx])
			}
			matches := reqRegex.FindStringSubmatch(line)
			if len(matches) >= 2 {
				name := matches[1]
				version := "*"
				if len(matches) >= 4 && matches[3] != "" {
					version = matches[3]
				}
				key := name + "@" + version
				if !seen[key] {
					seen[key] = true
					allDeps = append(allDeps, ParsedDependency{
						Name:      name,
						Version:   version,
						Ecosystem: "PyPI",
						Direct:    true,
						FilePath:  reqPath,
					})
				}
			}
		}
	}

	// 2. pyproject.toml
	pyprojectPath := filepath.Join(dir, "pyproject.toml")
	if data, err := os.ReadFile(pyprojectPath); err == nil {
		var pyproj struct {
			Project struct {
				Dependencies []string `toml:"dependencies"`
			} `toml:"project"`
			Tool struct {
				Poetry struct {
					Dependencies map[string]any `toml:"dependencies"`
				} `toml:"poetry"`
			} `toml:"tool"`
		}
		if err := toml.Unmarshal(data, &pyproj); err == nil {
			for _, depStr := range pyproj.Project.Dependencies {
				matches := reqRegex.FindStringSubmatch(depStr)
				if len(matches) >= 2 {
					name := matches[1]
					version := "*"
					if len(matches) >= 4 && matches[3] != "" {
						version = matches[3]
					}
					key := name + "@" + version
					if !seen[key] {
						seen[key] = true
						allDeps = append(allDeps, ParsedDependency{
							Name:      name,
							Version:   version,
							Ecosystem: "PyPI",
							Direct:    true,
							FilePath:  pyprojectPath,
						})
					}
				}
			}

			for name, verVal := range pyproj.Tool.Poetry.Dependencies {
				if strings.EqualFold(name, "python") {
					continue
				}
				version := "*"
				if s, ok := verVal.(string); ok {
					version = strings.TrimLeft(s, "^~>=< ")
				}
				key := name + "@" + version
				if !seen[key] {
					seen[key] = true
					allDeps = append(allDeps, ParsedDependency{
						Name:      name,
						Version:   version,
						Ecosystem: "PyPI",
						Direct:    true,
						FilePath:  pyprojectPath,
					})
				}
			}
		}
	}

	// 3. Pipfile.lock
	pipLockPath := filepath.Join(dir, "Pipfile.lock")
	if data, err := os.ReadFile(pipLockPath); err == nil {
		var lock struct {
			Default map[string]struct {
				Version string `json:"version"`
			} `json:"default"`
		}
		if err := json.Unmarshal(data, &lock); err == nil {
			for name, dep := range lock.Default {
				ver := strings.TrimPrefix(dep.Version, "==")
				if ver == "" {
					ver = "*"
				}
				key := name + "@" + ver
				if !seen[key] {
					seen[key] = true
					allDeps = append(allDeps, ParsedDependency{
						Name:      name,
						Version:   ver,
						Ecosystem: "PyPI",
						Direct:    false,
						FilePath:  pipLockPath,
					})
				}
			}
		}
	}

	return allDeps, nil
}
