package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ParsedDependency holds the normalized dependency metadata extracted from package manifests
type ParsedDependency struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"` // Go, PyPI, Maven, npm, crates.io
	Direct    bool   `json:"direct"`
	License   string `json:"license"`
	FilePath  string `json:"file_path"`
}

// Parser defines the interface for language-specific manifest parsers
type Parser interface {
	Ecosystem() string
	CanParse(dir string) bool
	Parse(dir string) ([]ParsedDependency, error)
}

// AllParsers returns all registered language parsers
func AllParsers() []Parser {
	return []Parser{
		&GoParser{},
		&NpmParser{},
		&PyPiParser{},
		&MavenParser{},
		&CargoParser{},
	}
}

// DetectAndParse discovers all dependencies across supported ecosystems in a directory
func DetectAndParse(dir string) ([]ParsedDependency, error) {
	parsers := AllParsers()
	var allDeps []ParsedDependency
	seen := make(map[string]bool)

	matchedAny := false

	// First pass: root directory check
	for _, p := range parsers {
		if p.CanParse(dir) {
			matchedAny = true
			deps, err := p.Parse(dir)
			if err != nil {
				continue
			}
			for _, d := range deps {
				key := fmt.Sprintf("%s:%s:%s", d.Ecosystem, d.Name, d.Version)
				if !seen[key] {
					seen[key] = true
					allDeps = append(allDeps, d)
				}
			}
		}
	}

	// Second pass: walk subdirectories (shallow, max depth 3) to find monorepo or submodule manifests
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return nil
		}
		if path == dir {
			return nil
		}
		// Skip hidden dirs, node_modules, vendor, target, build
		base := info.Name()
		if strings.HasPrefix(base, ".") || base == "node_modules" || base == "vendor" || base == "target" || base == ".git" {
			return filepath.SkipDir
		}
		rel, _ := filepath.Rel(dir, path)
		if strings.Count(rel, string(filepath.Separator)) > 2 {
			return filepath.SkipDir
		}

		for _, p := range parsers {
			if p.CanParse(path) {
				matchedAny = true
				deps, err := p.Parse(path)
				if err != nil {
					continue
				}
				for _, d := range deps {
					key := fmt.Sprintf("%s:%s:%s", d.Ecosystem, d.Name, d.Version)
					if !seen[key] {
						seen[key] = true
						allDeps = append(allDeps, d)
					}
				}
			}
		}
		return nil
	})

	if !matchedAny && len(allDeps) == 0 {
		return nil, fmt.Errorf("no recognized package manifests found (go.mod, package.json, requirements.txt, pom.xml, Cargo.toml)")
	}

	return allDeps, nil
}

// ParseByLanguage parses manifests targeting a specific ecosystem/language
func ParseByLanguage(dir string, lang string) ([]ParsedDependency, error) {
	lang = strings.ToLower(strings.TrimSpace(lang))
	var p Parser
	switch lang {
	case "go", "golang":
		p = &GoParser{}
	case "javascript", "typescript", "js", "ts", "npm", "node":
		p = &NpmParser{}
	case "python", "py", "pypi":
		p = &PyPiParser{}
	case "java", "maven", "gradle":
		p = &MavenParser{}
	case "rust", "cargo", "crates.io":
		p = &CargoParser{}
	default:
		return DetectAndParse(dir)
	}

	if !p.CanParse(dir) {
		// Try recursive search for this specific parser
		var allDeps []ParsedDependency
		seen := make(map[string]bool)
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || !info.IsDir() {
				return nil
			}
			base := info.Name()
			if strings.HasPrefix(base, ".") || base == "node_modules" || base == "vendor" || base == "target" || base == ".git" {
				return filepath.SkipDir
			}
			if p.CanParse(path) {
				deps, err := p.Parse(path)
				if err == nil {
					for _, d := range deps {
						key := fmt.Sprintf("%s:%s:%s", d.Ecosystem, d.Name, d.Version)
						if !seen[key] {
							seen[key] = true
							allDeps = append(allDeps, d)
						}
					}
				}
			}
			return nil
		})
		if len(allDeps) > 0 {
			return allDeps, nil
		}
		return nil, fmt.Errorf("no %s manifests detected in %s", lang, dir)
	}

	return p.Parse(dir)
}
