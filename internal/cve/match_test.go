package cve_test

import (
	"testing"

	"github.com/sysrqio/crafttrace/internal/cve"
	"github.com/sysrqio/crafttrace/internal/sbom"
)

func TestMatchFixtureOffline(t *testing.T) {
	components := []sbom.Component{
		{Name: "lodash", Version: "4.17.20"},
		{Name: "pillow", Version: "9.0.0"},
	}
	summary, err := cve.MatchComponents(components, false)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Counts[cve.SeverityHigh] < 1 {
		t.Fatalf("expected high severity match, counts=%v", summary.Counts)
	}
	if summary.Counts[cve.SeverityCritical] < 1 {
		t.Fatalf("expected critical severity match, counts=%v", summary.Counts)
	}
}

func TestExceedsFailOn(t *testing.T) {
	s := cve.Summary{Counts: map[string]int{cve.SeverityCritical: 1}}
	if !s.ExceedsFailOn("critical") {
		t.Fatal("expected fail on critical")
	}
	if !s.ExceedsFailOn("high") {
		t.Fatal("critical should fail on high threshold")
	}
}
