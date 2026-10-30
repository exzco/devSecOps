package parser

import (
	"bufio"
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// MavenParser parses Java pom.xml and Gradle build files
type MavenParser struct{}

func (p *MavenParser) Ecosystem() string {
	return "Maven"
}

func (p *MavenParser) CanParse(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "pom.xml")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "build.gradle")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "build.gradle.kts")); err == nil {
		return true
	}
	return false
}

type pomProject struct {
	XMLName      xml.Name `xml:"project"`
	Properties   properties `xml:"properties"`
	Dependencies struct {
		Dependency []pomDependency `xml:"dependency"`
	} `xml:"dependencies"`
	DependencyManagement struct {
		Dependencies struct {
			Dependency []pomDependency `xml:"dependency"`
		} `xml:"dependencies"`
	} `xml:"dependencyManagement"`
}

type properties struct {
	Entries map[string]string
}

func (p *properties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	p.Entries = make(map[string]string)
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch elem := t.(type) {
		case xml.StartElement:
			var val string
			if err := d.DecodeElement(&val, &elem); err == nil {
				p.Entries[elem.Name.Local] = val
			}
		case xml.EndElement:
			if elem == start.End() {
				return nil
			}
		}
	}
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

var gradleDepRegex = regexp.MustCompile(`(?:implementation|api|compileOnly|runtimeOnly|testImplementation|compile)\s*[\('"]+([^:'"\s]+):([^:'"\s]+):([^'"\s]+)`)

func (p *MavenParser) Parse(dir string) ([]ParsedDependency, error) {
	var allDeps []ParsedDependency
	seen := make(map[string]bool)

	// 1. pom.xml
	pomPath := filepath.Join(dir, "pom.xml")
	if data, err := os.ReadFile(pomPath); err == nil {
		var pom pomProject
		if err := xml.Unmarshal(data, &pom); err == nil {
			resolveVersion := func(ver string) string {
				ver = strings.TrimSpace(ver)
				if strings.HasPrefix(ver, "${") && strings.HasSuffix(ver, "}") {
					propKey := strings.TrimSuffix(strings.TrimPrefix(ver, "${"), "}")
					if resolved, ok := pom.Properties.Entries[propKey]; ok {
						return resolved
					}
				}
				if ver == "" {
					return "*"
				}
				return ver
			}

			addDep := func(d pomDependency, direct bool) {
				g := strings.TrimSpace(d.GroupID)
				a := strings.TrimSpace(d.ArtifactID)
				if g == "" || a == "" {
					return
				}
				v := resolveVersion(d.Version)
				name := g + ":" + a
				key := name + "@" + v
				if !seen[key] {
					seen[key] = true
					allDeps = append(allDeps, ParsedDependency{
						Name:      name,
						Version:   v,
						Ecosystem: "Maven",
						Direct:    direct,
						FilePath:  pomPath,
					})
				}
			}

			for _, d := range pom.Dependencies.Dependency {
				addDep(d, true)
			}
			for _, d := range pom.DependencyManagement.Dependencies.Dependency {
				addDep(d, false)
			}
		}
	}

	// 2. build.gradle / build.gradle.kts
	for _, fname := range []string{"build.gradle", "build.gradle.kts"} {
		gPath := filepath.Join(dir, fname)
		if file, err := os.Open(gPath); err == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "//") {
					continue
				}
				matches := gradleDepRegex.FindStringSubmatch(line)
				if len(matches) == 4 {
					group := matches[1]
					artifact := matches[2]
					version := matches[3]
					name := group + ":" + artifact
					key := name + "@" + version
					if !seen[key] {
						seen[key] = true
						allDeps = append(allDeps, ParsedDependency{
							Name:      name,
							Version:   version,
							Ecosystem: "Maven",
							Direct:    true,
							FilePath:  gPath,
						})
					}
				}
			}
			_ = file.Close()
		}
	}

	return allDeps, nil
}
