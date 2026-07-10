package parser

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

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
			if dep, ok := parseGoModLine(line); ok {
				deps = append(deps, dep)
			}
			continue
		}

		if strings.HasPrefix(line, "require ") {
			raw := strings.TrimPrefix(line, "require ")
			if dep, ok := parseGoModLine(raw); ok {
				deps = append(deps, dep)
			}
		}
	}

	return deps, scanner.Err()
}

func parseGoModLine(line string) (ParsedDependency, bool) {
	isIndirect := strings.Contains(line, "// indirect")
	// 去除注释部分
	if idx := strings.Index(line, "//"); idx != -1 {
		line = strings.TrimSpace(line[:idx])
	}

	parts := strings.Fields(line)
	if len(parts) >= 2 {
		return ParsedDependency{
			Name:      parts[0],
			Version:   parts[1],
			Ecosystem: "Go",
			Direct:    !isIndirect,
		}, true
	}
	return ParsedDependency{}, false
}
