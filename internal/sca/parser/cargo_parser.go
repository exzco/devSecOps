package parser

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// CargoParser parses Rust Cargo.lock and Cargo.toml
type CargoParser struct{}

func (p *CargoParser) Ecosystem() string {
	return "crates.io"
}

func (p *CargoParser) CanParse(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "Cargo.lock")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "Cargo.toml")); err == nil {
		return true
	}
	return false
}

type cargoLock struct {
	Packages []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
		Source  string `toml:"source"`
	} `toml:"package"`
}

type cargoToml struct {
	Package struct {
		Name string `toml:"name"`
	} `toml:"package"`
	Dependencies    map[string]any `toml:"dependencies"`
	DevDependencies map[string]any `toml:"dev-dependencies"`
	BuildDeps       map[string]any `toml:"build-dependencies"`
}

func (p *CargoParser) Parse(dir string) ([]ParsedDependency, error) {
	var allDeps []ParsedDependency
	seen := make(map[string]bool)

	// Collect direct dependency names from Cargo.toml if present
	directMap := make(map[string]bool)
	cargoTomlPath := filepath.Join(dir, "Cargo.toml")
	if data, err := os.ReadFile(cargoTomlPath); err == nil {
		var manifest cargoToml
		if err := toml.Unmarshal(data, &manifest); err == nil {
			for depName := range manifest.Dependencies {
				directMap[depName] = true
			}
			for depName := range manifest.DevDependencies {
				directMap[depName] = false
			}
			for depName := range manifest.BuildDeps {
				directMap[depName] = false
			}
		}
	}

	// 1. Try Cargo.lock first for exact resolved versions
	cargoLockPath := filepath.Join(dir, "Cargo.lock")
	if data, err := os.ReadFile(cargoLockPath); err == nil {
		var lock cargoLock
		if err := toml.Unmarshal(data, &lock); err == nil {
			for _, pkg := range lock.Packages {
				name := strings.TrimSpace(pkg.Name)
				ver := strings.TrimSpace(pkg.Version)
				if name == "" || ver == "" {
					continue
				}
				key := name + "@" + ver
				if !seen[key] {
					seen[key] = true
					isDirect, found := directMap[name]
					if !found && len(directMap) == 0 {
						isDirect = true
					}
					allDeps = append(allDeps, ParsedDependency{
						Name:      name,
						Version:   ver,
						Ecosystem: "crates.io",
						Direct:    isDirect,
						FilePath:  cargoLockPath,
					})
				}
			}
			if len(allDeps) > 0 {
				return allDeps, nil
			}
		}
	}

	// 2. Fallback to Cargo.toml directly
	if len(directMap) > 0 {
		var manifest cargoToml
		if data, err := os.ReadFile(cargoTomlPath); err == nil && toml.Unmarshal(data, &manifest) == nil {
			extract := func(deps map[string]any, direct bool) {
				for name, val := range deps {
					ver := "*"
					switch v := val.(type) {
					case string:
						ver = strings.TrimLeft(v, "^~>=< ")
					case map[string]any:
						if sv, ok := v["version"].(string); ok {
							ver = strings.TrimLeft(sv, "^~>=< ")
						}
					}
					if ver == "" {
						ver = "*"
					}
					key := name + "@" + ver
					if !seen[key] {
						seen[key] = true
						allDeps = append(allDeps, ParsedDependency{
							Name:      name,
							Version:   ver,
							Ecosystem: "crates.io",
							Direct:    direct,
							FilePath:  cargoTomlPath,
						})
					}
				}
			}
			extract(manifest.Dependencies, true)
			extract(manifest.DevDependencies, false)
			extract(manifest.BuildDeps, false)
		}
	}

	return allDeps, nil
}
