package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsers(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Test Go parser
	goModContent := `module example.com/test
go 1.25
require (
	github.com/gin-gonic/gin v1.9.1
	github.com/stretchr/testify v1.8.4 // indirect
)
require golang.org/x/crypto v0.14.0
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goModContent), 0644); err != nil {
		t.Fatal(err)
	}

	goParser := &GoParser{}
	if !goParser.CanParse(tmpDir) {
		t.Errorf("GoParser CanParse returned false")
	}
	goDeps, err := goParser.Parse(tmpDir)
	if err != nil {
		t.Fatalf("GoParser.Parse failed: %v", err)
	}
	if len(goDeps) != 3 {
		t.Fatalf("expected 3 go dependencies, got %d", len(goDeps))
	}

	// 2. Test Cargo parser (Rust)
	rustDir := filepath.Join(tmpDir, "rust_project")
	_ = os.MkdirAll(rustDir, 0755)
	cargoLock := `version = 3
[[package]]
name = "time"
version = "0.1.43"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "libc"
version = "0.2.140"
`
	cargoToml := `[package]
name = "rust_test"
version = "0.1.0"

[dependencies]
time = "0.1"
`
	_ = os.WriteFile(filepath.Join(rustDir, "Cargo.lock"), []byte(cargoLock), 0644)
	_ = os.WriteFile(filepath.Join(rustDir, "Cargo.toml"), []byte(cargoToml), 0644)

	cargoParser := &CargoParser{}
	if !cargoParser.CanParse(rustDir) {
		t.Errorf("CargoParser CanParse returned false")
	}
	cargoDeps, err := cargoParser.Parse(rustDir)
	if err != nil {
		t.Fatalf("CargoParser.Parse failed: %v", err)
	}
	if len(cargoDeps) != 2 {
		t.Fatalf("expected 2 cargo dependencies, got %d", len(cargoDeps))
	}
	var timeDep ParsedDependency
	for _, d := range cargoDeps {
		if d.Name == "time" {
			timeDep = d
		}
	}
	if timeDep.Name != "time" || timeDep.Version != "0.1.43" || !timeDep.Direct || timeDep.Ecosystem != "crates.io" {
		t.Errorf("unexpected time dep: %+v", timeDep)
	}

	// 3. Test Python parser
	pyDir := filepath.Join(tmpDir, "python_project")
	_ = os.MkdirAll(pyDir, 0755)
	reqTxt := `requests==2.28.1
flask>=2.0.0
# some comment
urllib3~=1.26.5
`
	_ = os.WriteFile(filepath.Join(pyDir, "requirements.txt"), []byte(reqTxt), 0644)
	pyParser := &PyPiParser{}
	pyDeps, err := pyParser.Parse(pyDir)
	if err != nil {
		t.Fatalf("PyPiParser failed: %v", err)
	}
	if len(pyDeps) != 3 {
		t.Fatalf("expected 3 python dependencies, got %d", len(pyDeps))
	}

	// 4. Test NPM parser
	npmDir := filepath.Join(tmpDir, "npm_project")
	_ = os.MkdirAll(npmDir, 0755)
	pkgLock := `{
  "name": "test-pkg",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21",
      "dev": false,
      "license": "MIT"
    },
    "node_modules/jest": {
      "version": "29.0.0",
      "dev": true
    }
  }
}`
	_ = os.WriteFile(filepath.Join(npmDir, "package-lock.json"), []byte(pkgLock), 0644)
	npmParser := &NpmParser{}
	npmDeps, err := npmParser.Parse(npmDir)
	if err != nil {
		t.Fatalf("NpmParser failed: %v", err)
	}
	if len(npmDeps) != 2 {
		t.Fatalf("expected 2 npm dependencies, got %d", len(npmDeps))
	}

	// 5. Test Maven parser
	javaDir := filepath.Join(tmpDir, "java_project")
	_ = os.MkdirAll(javaDir, 0755)
	pomXML := `<project>
  <properties>
    <log4j.version>2.14.1</log4j.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>${log4j.version}</version>
    </dependency>
  </dependencies>
</project>`
	_ = os.WriteFile(filepath.Join(javaDir, "pom.xml"), []byte(pomXML), 0644)
	mavenParser := &MavenParser{}
	mavenDeps, err := mavenParser.Parse(javaDir)
	if err != nil {
		t.Fatalf("MavenParser failed: %v", err)
	}
	if len(mavenDeps) != 1 {
		t.Fatalf("expected 1 maven dependency, got %d", len(mavenDeps))
	}
	if mavenDeps[0].Name != "org.apache.logging.log4j:log4j-core" || mavenDeps[0].Version != "2.14.1" {
		t.Errorf("unexpected maven dep: %+v", mavenDeps[0])
	}

	// 6. Test DetectAndParse across monorepo directory
	detected, err := DetectAndParse(tmpDir)
	if err != nil {
		t.Fatalf("DetectAndParse failed: %v", err)
	}
	// Total dependencies = 3 (go) + 2 (rust) + 3 (python) + 2 (npm) + 1 (java) = 11
	if len(detected) != 11 {
		t.Fatalf("expected 11 detected dependencies across subprojects, got %d", len(detected))
	}
}
