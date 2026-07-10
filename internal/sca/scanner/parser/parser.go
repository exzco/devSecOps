package parser

import (
	"fmt"
)

// ParsedDependency 存放依赖解析中间数据
type ParsedDependency struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"` // Go, npm, PyPI, Maven
	Direct    bool   `json:"direct"`
	Licence   string `json:"licence"`
}

// Parser 各语言依赖解析器通用接口
type Parser interface {
	Ecosystem() string
	CanParse(dir string) bool
	Parse(dir string) ([]ParsedDependency, error)
}

// GetParserForDir 根据目录下的锁定文件选择合适的解析器
func GetParserForDir(dir string) (Parser, error) {
	parsers := []Parser{
		&GoParser{},
		&NpmParser{},
		&PyPiParser{},
		&MavenParser{},
	}

	for _, p := range parsers {
		if p.CanParse(dir) {
			return p, nil
		}
	}

	return nil, fmt.Errorf("未找到匹配的依赖文件 (go.mod, package-lock.json, requirements.txt, pom.xml)")
}

// DetectLanguage 自动化判断目录主语言
func DetectLanguage(dir string) string {
	if (&GoParser{}).CanParse(dir) {
		return "go"
	}
	if (&NpmParser{}).CanParse(dir) {
		return "javascript"
	}
	if (&PyPiParser{}).CanParse(dir) {
		return "python"
	}
	if (&MavenParser{}).CanParse(dir) {
		return "java"
	}
	return "unknown"
}
