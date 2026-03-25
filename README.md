# TeamPCP Supply Chain IOC Scanner

Detection script for the **TeamPCP multi-ecosystem supply chain attack** (March 19-24, 2026).

Scans for indicators of compromise across PyPI, npm, GitHub Actions, Docker, Kubernetes, and VS Code extensions.

## Quick Start

```bash
curl -O https://raw.githubusercontent.com/Kangwonland/teampcp-ioc-scan/main/teampcp_scan.sh
chmod +x teampcp_scan.sh
./teampcp_scan.sh
```

## Features

- **8 scanners**: filesystem, pypi, npm, docker, ghactions, network, kubernetes, openvsx
- **Single bash script** - zero dependencies beyond standard Linux tools
- **SHA256 hash verification** - 24 known malicious file hashes
- **Graceful degradation** - skips scanners when tools aren't available
- **JSON report** output for automation
- **Color-coded** terminal output

## Usage

```bash
./teampcp_scan.sh [OPTIONS]

Options:
  -p, --scan-path PATH    Root path to scan (default: $HOME)
  -o, --json-output FILE  Write JSON report to FILE
  -s, --scanners LIST     Scanners to run (default: all)
      --no-color          Disable colored output
      --no-dns            Skip DNS resolution checks
      --log-path PATH     Log files to scan for network IOCs
  -v, --verbose           Detailed output
  -q, --quiet             Findings only
  -h, --help              Show help
```

## What It Detects

| Scanner | Checks |
|---------|--------|
| **filesystem** | 12 malicious file paths, .pth files, proxy_server.py hash, systemd services |
| **pypi** | litellm 1.82.7/1.82.8 via pip + direct filesystem search |
| **npm** | 55 malicious packages, lock files, CanisterWorm signatures (7 hashes) |
| **docker** | Compromised trivy images across 4 registries (v0.69.4-0.69.6) |
| **ghactions** | Hijacked trivy-action, setup-trivy, KICS, AST action refs |
| **network** | C2 domain DNS, active connections to C2 IPs, log file analysis |
| **kubernetes** | node-setup-* pods, host-provisioner DaemonSets, kamikaze containers |
| **openvsx** | ast-results 2.53.0, cx-dev-assist 1.7.0 |

## Documentation

See [ANALYSIS.md](ANALYSIS.md) for:
- Full attack timeline and technical analysis
- Complete IOC list with SHA256 hashes
- MITRE ATT&CK mapping
- Response checklist

## References

- [Datadog Security Labs - TeamPCP Campaign](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/)
- [GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23) (Trivy)
- PYSEC-2026-2 (LiteLLM)

## License

MIT
