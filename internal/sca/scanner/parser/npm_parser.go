package parser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type NpmParser struct{}

func (p *NpmParser) Ecosystem() string {
	return "npm"
}

func (p *NpmParser) CanParse(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "package-lock.json"))
	return err == nil
}

type PackageLock struct {
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

func (p *NpmParser) Parse(dir string) ([]ParsedDependency, error) {
	filePath := filepath.Join(dir, "package-lock.json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var lock PackageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var deps []ParsedDependency
	seen := make(map[string]bool)

	// 处理 LockfileVersion >= 2 (packages 格式)
	if len(lock.Packages) > 0 {
		for pkgPath, pkg := range lock.Packages {
			if pkgPath == "" || pkg.Version == "" {
				continue
			}
			// 移除 "node_modules/" 前缀
			name := strings.TrimPrefix(pkgPath, "node_modules/")
			// 处理嵌套 node_modules (如 node_modules/a/node_modules/b)
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
					Licence:   pkg.License,
				})
			}
		}
	} else if len(lock.Dependencies) > 0 {
		// 回退处理 v1 格式
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
				})
			}
		}
	}

	return deps, nil
}
