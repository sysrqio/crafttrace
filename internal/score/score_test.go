package score_test

import (
	"testing"

	"github.com/sysrqio/crafttrace/internal/cve"
	"github.com/sysrqio/crafttrace/internal/sbom"
	"github.com/sysrqio/crafttrace/internal/score"
)

func TestComputeWithCritical(t *testing.T) {
	bom := sbom.NewBOM([]sbom.Component{{Name: "x", Version: "1", Licenses: []sbom.License{{License: sbom.LicenseChoice{ID: "MIT"}}}}})
	summary := cve.Summary{Counts: map[string]int{cve.SeverityCritical: 1, cve.SeverityHigh: 0, cve.SeverityMedium: 0, cve.SeverityLow: 0}}
	r := score.Compute(bom, summary, true)
	if r.Total >= r.Max {
		t.Fatalf("critical CVE should reduce score, got %d/%d", r.Total, r.Max)
	}
}

func TestComputeClean(t *testing.T) {
	bom := sbom.NewBOM([]sbom.Component{{Name: "x", Version: "1", Licenses: []sbom.License{{License: sbom.LicenseChoice{ID: "Apache-2.0"}}}}})
	summary := cve.Summary{Counts: map[string]int{cve.SeverityCritical: 0, cve.SeverityHigh: 0, cve.SeverityMedium: 0, cve.SeverityLow: 0}}
	r := score.Compute(bom, summary, true)
	if r.Total != r.Max {
		t.Fatalf("expected max score %d, got %d", r.Max, r.Total)
	}
}
