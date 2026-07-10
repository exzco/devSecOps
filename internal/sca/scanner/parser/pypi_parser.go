package parser

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type PyPiParser struct{}

func (p *PyPiParser) Ecosystem() string {
	return "PyPI"
}

func (p *PyPiParser) CanParse(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "requirements.txt"))
	return err == nil
}

var reqRegex = regexp.MustCompile(`^([a-zA-Z0-9_\-\.]+)\s*([=><~=!]*)\s*([a-zA-Z0-9_\-\.]+)?`)

func (p *PyPiParser) Parse(dir string) ([]ParsedDependency, error) {
	filePath := filepath.Join(dir, "requirements.txt")
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []ParsedDependency
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-r") || strings.HasPrefix(line, "-e") {
			continue
		}

		// 去掉行尾注释
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
				deps = append(deps, ParsedDependency{
					Name:      name,
					Version:   version,
					Ecosystem: "PyPI",
					Direct:    true,
				})
			}
		}
	}

	return deps, scanner.Err()
}
