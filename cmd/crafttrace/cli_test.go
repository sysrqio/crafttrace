package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func buildCLI(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	out := filepath.Join(t.TempDir(), "crafttrace")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = filepath.Join(root, "cmd", "crafttrace")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build crafttrace: %v\n%s", err, combined)
	}
	return out
}

func runCLI(t *testing.T, bin string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = os.Environ()
	var outBuf, errBuf execOutput
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("run crafttrace: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

type execOutput struct {
	b []byte
}

func (e *execOutput) Write(p []byte) (int, error) {
	e.b = append(e.b, p...)
	return len(p), nil
}

func (e *execOutput) String() string {
	return string(e.b)
}

func TestCLIExitFailOnCritical(t *testing.T) {
	bin := buildCLI(t)
	root := repoRoot(t)
	target := fmt.Sprintf("dir:%s", filepath.Join(root, "testdata", "manifests"))
	_, _, code := runCLI(t, bin, "audit", "--target", target, "--fail-on", "critical", "--no-color")
	if code != 2 {
		t.Fatalf("expected exit 2 for critical CVE, got %d", code)
	}
}

func TestCLIExitMinScore(t *testing.T) {
	bin := buildCLI(t)
	root := repoRoot(t)
	target := fmt.Sprintf("sbom:%s", filepath.Join(root, "testdata", "sbom", "sample.cdx.json"))
	_, _, code := runCLI(t, bin, "audit", "--target", target, "--fail-on", "critical", "--min-score", "101", "--no-color")
	if code != 2 {
		t.Fatalf("expected exit 2 for min-score 101, got %d", code)
	}
}

func TestCLIExitZeroWhenPolicyPasses(t *testing.T) {
	bin := buildCLI(t)
	root := repoRoot(t)
	target := fmt.Sprintf("sbom:%s", filepath.Join(root, "testdata", "sbom", "sample.cdx.json"))
	_, _, code := runCLI(t, bin, "audit", "--target", target, "--fail-on", "critical", "--min-score", "0", "--no-color")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
}

func TestCLIOutputFormats(t *testing.T) {
	bin := buildCLI(t)
	root := repoRoot(t)
	target := fmt.Sprintf("dir:%s", filepath.Join(root, "testdata", "manifests"))

	cases := []struct {
		format string
		needle string
	}{
		{"table", "CRA score"},
		{"cyclonedx-json", `"bomFormat": "CycloneDX"`},
		{"sarif", `"version": "2.1.0"`},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			stdout, _, code := runCLI(t, bin, "audit", "--target", target, "--output", tc.format, "--fail-on", "low", "--no-color")
			if code != 2 {
				t.Fatalf("expected exit 2 (policy), got %d", code)
			}
			if !strings.Contains(stdout, tc.needle) {
				t.Fatalf("output missing %q:\n%s", tc.needle, stdout)
			}
		})
	}
}
