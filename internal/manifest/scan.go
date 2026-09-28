package manifest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sysrqio/crafttrace/internal/sbom"
)

var manifestNames = map[string]bool{
	"go.mod":            true,
	"package-lock.json": true,
	"requirements.txt":  true,
	"Cargo.lock":        true,
}

// ScanDir walks a directory and collects components from known manifests.
func ScanDir(root string) ([]sbom.Component, error) {
	var components []sbom.Component
	seen := make(map[string]struct{})

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "vendor" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		base := d.Name()
		if !manifestNames[base] {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		parsed, err := ParseFile(path, base)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		for _, c := range parsed {
			key := c.Name + "@" + c.Version
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			c.Properties = append(c.Properties, sbom.Property{
				Name:  "crafttrace:manifest",
				Value: rel,
			})
			components = append(components, c)
		}
		return nil
	})
	return components, err
}

// ScanFile scans a single manifest file.
func ScanFile(path string) ([]sbom.Component, error) {
	base := filepath.Base(path)
	if !manifestNames[base] {
		return nil, fmt.Errorf("unsupported manifest file %q", base)
	}
	return ParseFile(path, base)
}

func ParseFile(path, name string) ([]sbom.Component, error) {
	switch name {
	case "go.mod":
		return parseGoMod(path)
	case "package-lock.json":
		return parsePackageLock(path)
	case "requirements.txt":
		return parseRequirements(path)
	case "Cargo.lock":
		return parseCargoLock(path)
	default:
		return nil, fmt.Errorf("unknown manifest %q", name)
	}
}

var goModRequire = regexp.MustCompile(`^\s*require\s+(\S+)\s+(\S+)`)

func parseGoMod(path string) ([]sbom.Component, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var components []sbom.Component
	sc := bufio.NewScanner(f)
	inBlock := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "require (") {
			inBlock = true
			continue
		}
		if inBlock {
			if line == ")" {
				inBlock = false
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && !strings.HasPrefix(fields[0], "//") {
				components = append(components, goComponent(fields[0], strings.TrimPrefix(fields[1], "v")))
			}
			continue
		}
		if m := goModRequire.FindStringSubmatch(line); len(m) == 3 {
			components = append(components, goComponent(m[1], strings.TrimPrefix(m[2], "v")))
		}
	}
	return components, sc.Err()
}

func goComponent(name, version string) sbom.Component {
	return sbom.Component{
		Type:    "library",
		Name:    name,
		Version: version,
		PURL:    fmt.Sprintf("pkg:golang/%s@%s", name, version),
		Licenses: []sbom.License{{
			License: sbom.LicenseChoice{Name: "unknown"},
		}},
	}
}

type npmLock struct {
	Packages map[string]struct {
		Version string `json:"version"`
		License string `json:"license"`
	} `json:"packages"`
	Dependencies map[string]struct {
		Version string `json:"version"`
	} `json:"dependencies"`
}

func parsePackageLock(path string) ([]sbom.Component, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var components []sbom.Component
	if len(lock.Packages) > 0 {
		for pkgPath, pkg := range lock.Packages {
			if pkgPath == "" || pkg.Version == "" {
				continue
			}
			name := strings.TrimPrefix(pkgPath, "node_modules/")
			lic := pkg.License
			if lic == "" {
				lic = "unknown"
			}
			components = append(components, sbom.Component{
				Type:    "library",
				Name:    name,
				Version: pkg.Version,
				PURL:    fmt.Sprintf("pkg:npm/%s@%s", name, pkg.Version),
				Licenses: []sbom.License{{
					License: sbom.LicenseChoice{Name: lic},
				}},
			})
		}
		return components, nil
	}
	for name, dep := range lock.Dependencies {
		if dep.Version == "" {
			continue
		}
		components = append(components, sbom.Component{
			Type:    "library",
			Name:    name,
			Version: dep.Version,
			PURL:    fmt.Sprintf("pkg:npm/%s@%s", name, dep.Version),
			Licenses: []sbom.License{{
				License: sbom.LicenseChoice{Name: "unknown"},
			}},
		})
	}
	return components, nil
}

func parseRequirements(path string) ([]sbom.Component, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var components []sbom.Component
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, version := splitReqLine(line)
		if name == "" {
			continue
		}
		components = append(components, sbom.Component{
			Type:    "library",
			Name:    name,
			Version: version,
			PURL:    fmt.Sprintf("pkg:pypi/%s@%s", name, version),
			Licenses: []sbom.License{{
				License: sbom.LicenseChoice{Name: "unknown"},
			}},
		})
	}
	return components, sc.Err()
}

func splitReqLine(line string) (name, version string) {
	seps := []string{"==", ">=", "<=", "~=", "!=", ">", "<"}
	for _, sep := range seps {
		if i := strings.Index(line, sep); i >= 0 {
			return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+len(sep):])
		}
	}
	return line, "*"
}

func parseCargoLock(path string) ([]sbom.Component, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var components []sbom.Component
	sc := bufio.NewScanner(f)
	inPkg := false
	var name, version string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "[[package]]" {
			if name != "" {
				components = append(components, cargoComponent(name, version))
			}
			name, version = "", ""
			inPkg = true
			continue
		}
		if !inPkg {
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			name = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		}
		if strings.HasPrefix(line, "version = ") {
			version = strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
		}
	}
	if name != "" {
		components = append(components, cargoComponent(name, version))
	}
	return components, sc.Err()
}

func cargoComponent(name, version string) sbom.Component {
	return sbom.Component{
		Type:    "library",
		Name:    name,
		Version: version,
		PURL:    fmt.Sprintf("pkg:cargo/%s@%s", name, version),
		Licenses: []sbom.License{{
			License: sbom.LicenseChoice{Name: "unknown"},
		}},
	}
}
