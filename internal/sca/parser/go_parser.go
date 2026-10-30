package parser

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// GoParser parses go.mod files
type GoParser struct{}

func (p *GoParser) Ecosystem() string {
	return "Go"
}

func (p *GoParser) CanParse(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "go.mod"))
	return err == nil
}

func (p *GoParser) Parse(dir string) ([]ParsedDependency, error) {
	filePath := filepath.Join(dir, "go.mod")
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []ParsedDependency
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	inRequireBlock := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		if line == "require (" {
			inRequireBlock = true
			continue
		}

		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		if inRequireBlock {
			if dep, ok := parseGoModLine(line, filePath); ok {
				key := dep.Name + "@" + dep.Version
				if !seen[key] {
					seen[key] = true
					deps = append(deps, dep)
				}
			}
			continue
		}

		if strings.HasPrefix(line, "require ") {
			raw := strings.TrimPrefix(line, "require ")
			if dep, ok := parseGoModLine(raw, filePath); ok {
				key := dep.Name + "@" + dep.Version
				if !seen[key] {
					seen[key] = true
					deps = append(deps, dep)
				}
			}
		}
	}

	return deps, scanner.Err()
}

func parseGoModLine(line, filePath string) (ParsedDependency, bool) {
	isIndirect := strings.Contains(line, "// indirect")
	if idx := strings.Index(line, "//"); idx != -1 {
		line = strings.TrimSpace(line[:idx])
	}

	parts := strings.Fields(line)
	if len(parts) >= 2 {
		name := parts[0]
		version := parts[1]
		return ParsedDependency{
			Name:      name,
			Version:   version,
			Ecosystem: "Go",
			Direct:    !isIndirect,
			FilePath:  filePath,
		}, true
	}
	return ParsedDependency{}, false
}
