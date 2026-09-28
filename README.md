# crafttrace

**crafttrace** is a local command-line tool for **Cyber Resilience Act (CRA) readiness** checks: it builds a simple SBOM inventory, summarizes known CVEs, and computes a readiness score. Processing stays on your machine — **no telemetry**.

> **Disclaimer:** This tool supports engineering workflows around SBOM and vulnerability visibility. It is **not legal advice** and does not certify EU CRA compliance. Consult qualified counsel for regulatory obligations.

## EU Cyber Resilience Act (context)

The EU [Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) introduces requirements for products with digital elements, including vulnerability handling and documentation expectations often supported by **SBOMs** and **security monitoring**. crafttrace helps teams practice:

- Generating or ingesting an SBOM (CycloneDX-oriented)
- Running a vulnerability summary (embedded matcher offline; optional [Grype](https://github.com/anchore/grype) when installed)
- Scoring readiness signals (inventory, scan completion, critical CVE posture, licenses)

## Requirements

- Go 1.22+ (to build from source)
- Optional: [Syft](https://github.com/anchore/syft) for `docker:` targets
- Optional: Grype for extended matching when present on `PATH`

## Install

```bash
make build
./bin/crafttrace version
```

Or:

```bash
go install github.com/sysrqio/crafttrace/cmd/crafttrace@latest
```

## Usage

```bash
# Audit a project directory (manifest discovery)
crafttrace audit --target dir:./my-app

# Single manifest file
crafttrace audit --target file:./package-lock.json

# Existing CycloneDX SBOM
crafttrace audit --target sbom:./sbom.cdx.json --output cyclonedx-json

# Container image (requires syft)
crafttrace audit --target docker:alpine:3.19

# JSON report and CI gate
crafttrace audit --target dir:./app --output json --fail-on high --min-score 80

# Config path hint
crafttrace config
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success; policies satisfied |
| 1 | Runtime or user error |
| 2 | Policy violation (`--fail-on` or `--min-score`) |

### Flags (`audit`)

| Flag | Description |
|------|-------------|
| `--target` | **Required.** `dir:<path>`, `file:<path>`, `sbom:<path>`, or `docker:<image>` |
| `--output` | `table` (default), `json`, `cyclonedx-json`, `sarif` |
| `--output-file` | Write the same output to a file |
| `--fail-on` | `critical` (default), `high`, `medium`, `low` |
| `--min-score` | Minimum CRA readiness score (0–100, default 0) |
| `--no-color` | Plain table output |
| `--verbose` | Progress on stderr |

## Supported manifests (MVP)

- `go.mod`
- `package-lock.json`
- `requirements.txt`
- `Cargo.lock`

## Development

```bash
make test
make lint
```

Tests use an **embedded CVE fixture database** so `go test ./...` passes **offline**.

## License

Apache-2.0 — see [LICENSE](LICENSE).
