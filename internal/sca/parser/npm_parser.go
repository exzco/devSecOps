package parser

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// NpmParser parses package-lock.json, package.json, and yarn.lock
type NpmParser struct{}

func (p *NpmParser) Ecosystem() string {
	return "npm"
}

func (p *NpmParser) CanParse(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "package-lock.json")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "yarn.lock")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
		return true
	}
	return false
}

type packageLock struct {
	LockfileVersion int `json:"lockfileVersion"`
	Packages        map[string]struct {
		Version  string `json:"version"`
		Dev      bool   `json:"dev"`
		License  string `json:"license"`
		InBundle bool   `json:"inBundle"`
	} `json:"packages"`
	Dependencies map[string]struct {
		Version string `json:"version"`
		Dev     bool   `json:"dev"`
	} `json:"dependencies"`
}

type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func (p *NpmParser) Parse(dir string) ([]ParsedDependency, error) {
	// 1. Try package-lock.json first
	lockPath := filepath.Join(dir, "package-lock.json")
	if data, err := os.ReadFile(lockPath); err == nil {
		var lock packageLock
		if err := json.Unmarshal(data, &lock); err == nil {
			var deps []ParsedDependency
			seen := make(map[string]bool)

			if len(lock.Packages) > 0 {
				for pkgPath, pkg := range lock.Packages {
					if pkgPath == "" || pkg.Version == "" {
						continue
					}
					name := strings.TrimPrefix(pkgPath, "node_modules/")
					if idx := strings.LastIndex(name, "node_modules/"); idx != -1 {
						name = name[idx+len("node_modules/"):]
					}

					key := name + "@" + pkg.Version
					if !seen[key] {
						seen[key] = true
						deps = append(deps, ParsedDependency{
							Name:      name,
							Version:   pkg.Version,
							Ecosystem: "npm",
							Direct:    !pkg.Dev,
							License:   pkg.License,
							FilePath:  lockPath,
						})
					}
				}
				if len(deps) > 0 {
					return deps, nil
				}
			}

			if len(lock.Dependencies) > 0 {
				for name, dep := range lock.Dependencies {
					if dep.Version == "" {
						continue
					}
					key := name + "@" + dep.Version
					if !seen[key] {
						seen[key] = true
						deps = append(deps, ParsedDependency{
							Name:      name,
							Version:   dep.Version,
							Ecosystem: "npm",
							Direct:    !dep.Dev,
							FilePath:  lockPath,
						})
					}
				}
				if len(deps) > 0 {
					return deps, nil
				}
			}
		}
	}

	// 2. Try yarn.lock
	yarnPath := filepath.Join(dir, "yarn.lock")
	if yarnDeps, err := parseYarnLock(yarnPath); err == nil && len(yarnDeps) > 0 {
		return yarnDeps, nil
	}

	// 3. Fallback to package.json
	pkgJSONPath := filepath.Join(dir, "package.json")
	if data, err := os.ReadFile(pkgJSONPath); err == nil {
		var pj packageJSON
		if err := json.Unmarshal(data, &pj); err == nil {
			var deps []ParsedDependency
			seen := make(map[string]bool)
			for name, ver := range pj.Dependencies {
				cleanVer := strings.TrimLeft(ver, "^~>=<v ")
				if cleanVer == "" {
					cleanVer = "*"
				}
				key := name + "@" + cleanVer
				if !seen[key] {
					seen[key] = true
					deps = append(deps, ParsedDependency{
						Name:      name,
						Version:   cleanVer,
						Ecosystem: "npm",
						Direct:    true,
						FilePath:  pkgJSONPath,
					})
				}
			}
			for name, ver := range pj.DevDependencies {
				cleanVer := strings.TrimLeft(ver, "^~>=<v ")
				if cleanVer == "" {
					cleanVer = "*"
				}
				key := name + "@" + cleanVer
				if !seen[key] {
					seen[key] = true
					deps = append(deps, ParsedDependency{
						Name:      name,
						Version:   cleanVer,
						Ecosystem: "npm",
						Direct:    false,
						FilePath:  pkgJSONPath,
					})
				}
			}
			return deps, nil
		}
	}

	return nil, nil
}

func parseYarnLock(filePath string) ([]ParsedDependency, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []ParsedDependency
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	var currentName string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasSuffix(line, ":") && !strings.HasPrefix(line, "version") {
			// Header line: "lodash@^4.17.15", "@babel/core@^7.0.0":
			raw := strings.TrimSuffix(line, ":")
			raw = strings.Trim(raw, "\"")
			parts := strings.Split(raw, ",")
			if len(parts) > 0 {
				first := strings.TrimSpace(strings.Trim(parts[0], "\""))
				if atIdx := strings.LastIndex(first, "@"); atIdx > 0 {
					currentName = first[:atIdx]
				}
			}
			continue
		}

		if strings.HasPrefix(line, "version ") && currentName != "" {
			parts := strings.SplitN(line, " ", 2)
			if len(parts) == 2 {
				ver := strings.Trim(parts[1], "\" ")
				key := currentName + "@" + ver
				if !seen[key] {
					seen[key] = true
					deps = append(deps, ParsedDependency{
						Name:      currentName,
						Version:   ver,
						Ecosystem: "npm",
						Direct:    false,
						FilePath:  filePath,
					})
				}
			}
			currentName = ""
		}
	}

	return deps, scanner.Err()
}
