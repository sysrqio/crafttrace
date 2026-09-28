package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sysrqio/crafttrace/internal/cve"
	"github.com/sysrqio/crafttrace/internal/docker"
	"github.com/sysrqio/crafttrace/internal/manifest"
	"github.com/sysrqio/crafttrace/internal/sbom"
	"github.com/sysrqio/crafttrace/internal/score"
)

// Options configures an audit run.
type Options struct {
	Target     string
	Output     string
	OutputFile string
	FailOn     string
	MinScore   int
	NoColor    bool
	Verbose    bool
	PreferGrype bool
}

// Report is the full audit result.
type Report struct {
	Target   string         `json:"target"`
	SBOM     *sbom.BOM      `json:"sbom"`
	CVE      cve.Summary    `json:"cve"`
	Score    score.Result   `json:"cra_score"`
}

// Run executes the audit pipeline.
func Run(opts Options) (Report, error) {
	components, targetLabel, err := resolveTarget(opts.Target)
	if err != nil {
		return Report{}, err
	}

	bom := sbom.NewBOM(components)
	cveSummary, err := cve.MatchComponents(components, opts.PreferGrype)
	if err != nil {
		return Report{}, err
	}

	sc := score.Compute(bom, cveSummary, true)

	return Report{
		Target: targetLabel,
		SBOM:   bom,
		CVE:   cveSummary,
		Score:  sc,
	}, nil
}

func resolveTarget(target string) ([]sbom.Component, string, error) {
	if target == "" {
		return nil, "", fmt.Errorf("--target is required (dir:|file:|sbom:|docker:)")
	}
	typ, rest, ok := strings.Cut(target, ":")
	if !ok || rest == "" {
		return nil, "", fmt.Errorf("invalid --target %q; use dir:<path>, file:<path>, sbom:<path>, or docker:<image>", target)
	}

	switch typ {
	case "dir":
		path, err := filepath.Abs(rest)
		if err != nil {
			return nil, "", err
		}
		st, err := os.Stat(path)
		if err != nil {
			return nil, "", err
		}
		if !st.IsDir() {
			return nil, "", fmt.Errorf("dir: path is not a directory: %s", path)
		}
		comps, err := manifest.ScanDir(path)
		return comps, "dir:" + path, err
	case "file":
		path, err := filepath.Abs(rest)
		if err != nil {
			return nil, "", err
		}
		comps, err := manifest.ScanFile(path)
		return comps, "file:" + path, err
	case "sbom":
		path, err := filepath.Abs(rest)
		if err != nil {
			return nil, "", err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, "", err
		}
		b, err := sbom.ParseCycloneDX(data)
		if err != nil {
			return nil, "", err
		}
		return b.Components, "sbom:" + path, nil
	case "docker":
		data, err := docker.GenerateSBOM(rest)
		if err != nil {
			return nil, "", err
		}
		b, err := sbom.ParseCycloneDX(data)
		if err != nil {
			return nil, "", err
		}
		return b.Components, "docker:" + rest, nil
	default:
		return nil, "", fmt.Errorf("unknown target type %q", typ)
	}
}

// PolicyViolation checks fail-on and min-score gates.
func PolicyViolation(r Report, failOn string, minScore int) bool {
	if r.Score.Total < minScore {
		return true
	}
	return r.CVE.ExceedsFailOn(failOn)
}
