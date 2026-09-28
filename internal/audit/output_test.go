package audit_test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sysrqio/crafttrace/internal/audit"
)

func loadManifestReport(t *testing.T) audit.Report {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "manifests")
	report, err := audit.Run(audit.Options{Target: "dir:" + root})
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func TestTableOutputSmoke(t *testing.T) {
	report := loadManifestReport(t)
	var buf bytes.Buffer
	if err := audit.WriteOutput(&buf, report, "table", true); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Target", "Components", "CRA score", "CVE summary", "critical", "Score breakdown:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("table output missing %q\n%s", want, out)
		}
	}
}

func TestCycloneDXJSONOutputSchemaFields(t *testing.T) {
	report := loadManifestReport(t)
	var buf bytes.Buffer
	if err := audit.WriteOutput(&buf, report, "cyclonedx-json", true); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["bomFormat"] != "CycloneDX" {
		t.Fatalf("bomFormat = %v", doc["bomFormat"])
	}
	if doc["specVersion"] != "1.5" {
		t.Fatalf("specVersion = %v", doc["specVersion"])
	}
	comps, ok := doc["components"].([]any)
	if !ok || len(comps) == 0 {
		t.Fatal("expected non-empty components array")
	}
}

func TestSARIFOutputSchemaFields(t *testing.T) {
	report := loadManifestReport(t)
	var buf bytes.Buffer
	if err := audit.WriteOutput(&buf, report, "sarif", true); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["version"] != "2.1.0" {
		t.Fatalf("version = %v", doc["version"])
	}
	schema, _ := doc["$schema"].(string)
	if !strings.Contains(schema, "sarif") {
		t.Fatalf("$schema = %q", schema)
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) == 0 {
		t.Fatal("expected runs array")
	}
	run0, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatal("run[0] type")
	}
	tool, ok := run0["tool"].(map[string]any)
	if !ok {
		t.Fatal("tool object")
	}
	driver, ok := tool["driver"].(map[string]any)
	if !ok {
		t.Fatal("driver object")
	}
	if driver["name"] != "crafttrace" {
		t.Fatalf("driver name = %v", driver["name"])
	}
	results, ok := run0["results"].([]any)
	if !ok || len(results) == 0 {
		t.Fatal("expected SARIF results from fixture CVEs")
	}
}
