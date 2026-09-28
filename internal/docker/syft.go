package docker

import (
	"fmt"
	"os/exec"
)

// GenerateSBOM runs syft when available to produce CycloneDX JSON bytes.
func GenerateSBOM(image string) ([]byte, error) {
	path, err := exec.LookPath("syft")
	if err != nil {
		return nil, fmt.Errorf("docker target requires syft on PATH; install from https://github.com/anchore/syft or use dir:/file:/sbom: targets")
	}
	cmd := exec.Command(path, image, "-o", "cyclonedx-json")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("syft failed: %s", string(ee.Stderr))
		}
		return nil, fmt.Errorf("syft: %w", err)
	}
	return out, nil
}
