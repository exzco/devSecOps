package parser

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
)

type MavenParser struct{}

func (p *MavenParser) Ecosystem() string {
	return "Maven"
}

func (p *MavenParser) CanParse(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "pom.xml"))
	return err == nil
}

type PomProject struct {
	XMLName      xml.Name `xml:"project"`
	Dependencies struct {
		Dependency []PomDependency `xml:"dependency"`
	} `xml:"dependencies"`
	DependencyManagement struct {
		Dependencies struct {
			Dependency []PomDependency `xml:"dependency"`
		} `xml:"dependencies"`
	} `xml:"dependencyManagement"`
}

type PomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Optional   bool   `xml:"optional"`
}

func (p *MavenParser) Parse(dir string) ([]ParsedDependency, error) {
	filePath := filepath.Join(dir, "pom.xml")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var pom PomProject
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, err
	}

	var deps []ParsedDependency
	seen := make(map[string]bool)

	addDep := func(d PomDependency, direct bool) {
		groupID := strings.TrimSpace(d.GroupID)
		artifactID := strings.TrimSpace(d.ArtifactID)
		version := strings.TrimSpace(d.Version)

		if groupID == "" || artifactID == "" {
			return
		}
		if version == "" {
			version = "*"
		}

		name := groupID + ":" + artifactID
		key := name + "@" + version
		if !seen[key] {
			seen[key] = true
			deps = append(deps, ParsedDependency{
				Name:      name,
				Version:   version,
				Ecosystem: "Maven",
				Direct:    direct,
			})
		}
	}

	for _, dep := range pom.Dependencies.Dependency {
		addDep(dep, true)
	}

	for _, dep := range pom.DependencyManagement.Dependencies.Dependency {
		addDep(dep, false)
	}

	return deps, nil
}
