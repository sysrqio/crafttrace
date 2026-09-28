package docker_test

import (
	"testing"

	"github.com/sysrqio/crafttrace/internal/docker"
)

func TestDockerWithoutSyft(t *testing.T) {
	_, err := docker.GenerateSBOM("alpine:latest")
	if err == nil {
		t.Skip("syft is installed; skipping error path test")
	}
}
