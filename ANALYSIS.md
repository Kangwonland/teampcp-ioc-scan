# TeamPCP Supply Chain Campaign Analysis

## 1. Overview

2026년 3월 19-24일, **TeamPCP**로 알려진 위협 행위자가 5일간 5개 소프트웨어 생태계에 걸친 대규모 공급망 공격을 수행했습니다. 이 공격은 탈취한 자격 증명을 이용해 인기 오픈소스 프로젝트의 공식 배포 채널에 악성 코드를 주입한 것이 특징입니다.

### Impact Summary

| Ecosystem | Target | Affected |
|-----------|--------|----------|
| PyPI | litellm | v1.82.7, v1.82.8 |
| Docker Hub/GHCR/ECR | aquasec/trivy | v0.69.4-0.69.6 |
| GitHub Actions | trivy-action, setup-trivy, KICS, AST | 76+ tags |
| npm | 55+ packages (CanisterWorm) | @emilgroup, @opengov, etc. |
| OpenVSX | ast-results, cx-dev-assist | 2 extensions |

### Attribution

- **Actor**: TeamPCP
- **Strings**: `TeamPCP`, `TeamPCP Cloud stealer`, `tpcp.tar.gz`, `TeamPCP Owns Aqua Security.`
- **GitHub accounts**: `Argon-DevOps-Mgt`, `aqua-bot`, `cx-plugins-releases`
- **Advisory IDs**: GHSA-69fq-xp46-6x23 (Trivy), PYSEC-2026-2 (LiteLLM)

---

## 2. Attack Timeline

| Date (UTC) | Event | Source |
|------------|-------|--------|
| **Mar 19, ~17:43** | `setup-trivy`, `trivy-action` tags force-pushed (76/77 tags) | StepSecurity |
| **Mar 19, 18:22** | Malicious `trivy` v0.69.4 published to Docker Hub, GHCR, ECR | Datadog |
| **Mar 19, ~21:31** | `aquasecurity/tfsec` compromised; curl exfil to Cloudflare tunnel | StepSecurity |
| **Mar 19, ~21:35** | `traceeshark`, `trivy-action` additional workflow injections | StepSecurity |
| **Mar 19, ~21:42** | trivy v0.69.4 exposure closed (~3h window) | StepSecurity |
| **Mar 20, 00:08** | ~100 spam bot accounts flood Trivy discussion #10420 | Datadog |
| **Mar 20-22** | **CanisterWorm** npm worm propagates; 28 @emilgroup pkgs in <60s | Aikido, JFrog |
| **Mar 22, 15:43** | `aquasec/trivy:0.69.5` pushed to Docker Hub | Datadog |
| **Mar 22, 16:34** | `aquasec/trivy:0.69.6` pushed to Docker Hub | Datadog |
| **Mar 22, 20:31** | `Argon-DevOps-Mgt` defacement: 44 Aqua repos renamed `tpcp-docs-*` | Datadog |
| **Mar 23, 12:58** | Checkmarx KICS/AST GitHub Actions compromised (35 tags) | Wiz |
| **Mar 23, 14:31** | `krrishdholakia` PAT used to push malicious workflows to litellm repos | Datadog |
| **Mar 24** | **litellm 1.82.7, 1.82.8** published to PyPI | Datadog |
| **Mar 24, 12:44** | ~125 spam bot accounts target LiteLLM issue #24512 | Datadog |

---

## 3. Attack Vector Analysis

### 3.1 PyPI - litellm (v1.82.7, v1.82.8)

**Source**: [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/), PYSEC-2026-2

**Initial Access**: 공격자가 BerriAI/litellm 메인테이너 `krrishdholakia`의 PAT를 탈취하여 CI/CD 파이프라인에 악성 워크플로(`test.yml`)를 주입. 이를 통해 `PYPI_PUBLISH` 토큰을 수집.

**v1.82.7 Payload Chain**:
1. `litellm/proxy/proxy_server.py`에 base64 인코딩된 페이로드 주입
2. 프록시 모듈 import 시 실행 -> `p.py` stager 드롭
3. 환경변수, SSH키, 클라우드 자격증명, K8s 토큰, Docker config, 셸 히스토리, DB 자격증명, 지갑 파일, CI/CD 시크릿 수집
4. AES-256 세션키 + RSA-4096 키 래핑으로 암호화
5. `models.litellm.cloud`로 `X-Filename: tpcp.tar.gz` 헤더와 함께 유출
6. Persistence: `~/.config/sysmon/sysmon.py` + `sysmon.service` systemd 유닛 설치
7. `checkmarx.zone/raw`로 비콘 -> `/tmp/pglog` 다운로드 및 실행
8. K8s 서비스 어카운트 토큰 발견 시 특권 `node-setup-*` Pod 생성

**v1.82.8 Payload Chain**:
- `litellm_init.pth` 파일 포함 (Python `.pth` 메커니즘 악용)
- `.pth` 파일은 Python 인터프리터 시작 시 자동 실행 -> litellm import 불필요
- 동일 페이로드 실행

**SHA256 Hashes**:
| Artifact | SHA256 |
|----------|--------|
| litellm-1.82.7.whl | `8395c3268d5c5dbae1c7c6d4bb3c318c752ba4608cfcd90eb97ffb94a910eac2` |
| litellm-1.82.8.whl | `d2a0d5f564628773b6af7b9c11f6b86531a875bd2d186d7081ab62748a800ebb` |
| litellm-1.82.7.tar.gz | `8a2a05fd8bdc329c8a86d2d08229d167500c01ecad06e40477c49fb0096efdea` |
| litellm-1.82.8.tar.gz | `d39f4e7a218053cce976c91eacf184cf09a6960c731cc9d66d8e1a53406593a5` |
| proxy_server.py (malicious) | `a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b` |
| litellm_init.pth (malicious) | `71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238` |

### 3.2 Docker/GitHub Actions - Trivy

**Source**: StepSecurity blog, [GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)

**Initial Access**: 탈취된 자격증명으로 Aqua Security의 trivy 리포지토리에 접근.

**Docker Images**:
- `docker.io/aquasec/trivy`, `ghcr.io/aquasecurity/trivy`, `public.ecr.aws/aquasecurity/trivy` v0.69.4-0.69.6
- `mirror.gcr.io`로 자동 전파됨
- deb/rpm 패키지 및 `get.trivy.dev` 설치 스크립트도 영향

**GitHub Actions**:
- `aquasecurity/setup-trivy`: 7개 태그 전부 교체 (0.2.0-0.2.6)
- `aquasecurity/trivy-action`: 76/77 태그 force-push (v-prefix 태그와 0.35.0 제외)

**Malware Behavior**:
- `/proc/*/environ` 스캔으로 SSH 및 환경 시크릿 수집
- `Runner.Worker` 프로세스 메모리 덤프 (`/proc/<pid>/mem`)
- 메모리 내 패턴: `{"value":"<secret>","isSecret":true}`
- 50+ 파일시스템 자격증명 경로 탐색
- AES-256-CBC + RSA-OAEP 암호화 후 `scan.aquasecurtiy.org`로 유출

**Imposter Commits** (spoofed author dates):

| Repository | Commit | Impersonation |
|------------|--------|---------------|
| actions/checkout | `70379aad1a8b` | Guillermo Rauch |
| aquasecurity/trivy | `1885610c6a34` | DmitriyLewen |
| aquasecurity/setup-trivy | `8afa9b9f9183` | Tomochika Hara |
| aquasecurity/trivy-action | `ddb9da4475c1` | (imposter) |

**Docker Image Hashes**:
| Image | SHA256 |
|-------|--------|
| aquasec/trivy:0.69.5 | `f69a8a4180c43fc427532ddde34a256acbd041a0a07844cf7e4d3e0434e5bcd1` |
| aquasec/trivy:0.69.6 | `dd8beb3b40df080b3fd7f9a0f5a1b02f3692f65c68980f46da8328ce8bb788ef` |

**Trivy Binary Hashes (v0.69.4)**:
| Platform | SHA256 |
|----------|--------|
| Linux-64 | `822dd269ec10459572dfaaefe163dae693c344249a0161953f0d5cdd110bd2a0` |
| macOS-ARM64 | `6328a34b26a63423b555a61f89a6a0525a534e9c88584c815d937910f1ddd538` |
| Windows-64 | `0880819ef821cff918960a39c1c1aada55a5593c61c608ea9215da858a86e349` |

### 3.3 GitHub Actions - Checkmarx KICS/AST

**Source**: Wiz.io KICS blog, Datadog

**Initial Access**: `cx-plugins-releases` (ID: 225848595) 계정 사용.

**Affected**:
- `Checkmarx/kics-github-action`: v1.1 포함 v1-v2.1.20 범위의 35개 태그 hijacked
- `Checkmarx/ast-github-action`: v2.3.28

**Payload** (`setup.sh`):
- 환경변수 수집, SSH키 추출
- `Runner.Worker` 프로세스 메모리 덤프
- AWS IMDSv1/v2 메타데이터 엔드포인트 쿼리
- K8s API 토큰 악용
- AES-256-CBC + RSA 공개키 래핑 후 `checkmarx.zone`로 유출
- Fallback: `docs-tpcp` 리포지토리에 GitHub Release asset으로 업로드

**Hash**:
- environmentAuthChecker.js: `527f795a201a6bc114394c4cfd1c74dce97381989f51a4661aafbc93a4439e90`

### 3.4 npm - CanisterWorm

**Source**: Aikido.dev, JFrog, StepSecurity

**Mechanism**: 자가 전파 npm 웜. 탈취된 npm 토큰으로 패키지 게시 권한을 획득하여 패치 버전을 올리고 악성 코드를 주입.

**Worm Behavior**:
1. `"postinstall": "node index.js"` 트리거
2. `.npmrc`, 환경변수 (`NPM_TOKEN`, `NPM_TOKENS`), npm config에서 토큰 수집
3. 토큰별 게시 가능 패키지 열거 (`getOwnedPackages`)
4. 패치 버전 증가 (`bumpPatch`), 원본 README 유지
5. 악성 코드 주입 후 `npm publish --access public --tag latest`
6. 28개 @emilgroup 패키지 60초 이내 감염

**C2**: ICP canister (`tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`)
- Motoko 기반 메서드: `get_latest_link`, `http_request`, `update_link`
- ~50분 폴링 간격, 5분 초기 대기

**npm Worm Code Indicators**:
- 함수명: `findNpmTokens()`, `g()`, `e(l)`, `bumpPatch()`, `getOwnedPackages()`, `deployWithToken()`
- `BASE64_PAYLOAD` 상수 (Python 백도어)
- YouTube.com 연결 확인을 킬 스위치로 사용

**Kubernetes Payload** (감염된 환경에서 K8s 접근 시):

| Target | DaemonSet | Container | Action |
|--------|-----------|-----------|--------|
| Iran (Asia/Tehran, fa_IR) | `host-provisioner-iran` | `kamikaze` | 파일시스템 삭제 + 강제 리부트 |
| Non-Iran | `host-provisioner-std` | `provisioner` | 영속 백도어 설치 |

K8s 스펙:
- Namespace: `kube-system`
- Image: `alpine:latest`
- Tolerations: `operator: Exists` (모든 노드 배포)
- HostPath: `/` -> `/mnt/host`

**Steganography** (v3.3):
- WAV 파일에 Base64 인코딩된 Python 모듈 삽입
- 8-bit mono, 44100 Hz RIFF WAV
- `bg_kube.wav`, `bg_prop.wav`

**npm Worm Hashes**:

| File | SHA256 |
|------|--------|
| index.js variant 1 | `e9b1e069efc778c1e77fb3f5fcc3bd3580bbc810604cbf4347897ddb4b8c163b` |
| index.js variant 2 | `61ff00a81b19624adaad425b9129ba2f312f4ab76fb5ddc2c628a5037d31a4ba` |
| index.js variant 3 | `0c0d206d5e68c0cf64d57ffa8bc5b1dad54f2dda52f24e96e02e237498cb9c3a` |
| index.js variant 4 | `c37c0ae9641d2e5329fcdee847a756bf1140fdb7f0b7c78a40fdc39055e7d926` |
| deploy.js variant 1 | `f398f06eefcd3558c38820a397e3193856e4e6e7c67f81ecc8e533275284b152` |
| deploy.js variant 2 | `7df6cef7ab9aae2ea08f2f872f6456b5d51d896ddda907a238cd6668ccdc4bb7` |
| deploy.js variant 3 | `5e2ba7c4c53fa6e0cef58011acdd50682cf83fb7b989712d2fcf1b5173bad956` |

### 3.5 OpenVSX Extensions

**Source**: Datadog

- `ast-results` v2.53.0 (SHA256: `65bd72fcddaf938cefdf55b3323ad29f649a65d4ddd6aea09afa974dfc7f105d`)
- `cx-dev-assist` v1.7.0 (SHA256: `744c9d61b66bcd2bb5474d9afeee6c00bb7e0cd32535781da188b80eb59383e0`)

---

## 4. Complete IOC List

### 4.1 C2 Infrastructure

| Domain | Context | IP |
|--------|---------|-----|
| `models.litellm.cloud` | LiteLLM exfiltration | - |
| `litellm.cloud` | 302 redirect to manpages.wtf | - |
| `checkmarx.zone` | C2 polling + KICS exfil | `83.142.209.11` |
| `scan.aquasecurtiy.org` | Trivy typosquat exfil | `45.148.10.212` |
| `aquasecurtiy.org` | Parent domain | `45.148.10.212` |
| `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io` | ICP canister C2 | - |
| `souls-entire-defined-routes.trycloudflare.com` | CanisterWorm v1 | - |
| `plug-tab-protective-relay.trycloudflare.com` | tfsec/traceeshark exfil | - |
| `investigation-launches-hearings-copying.trycloudflare.com` | Kamikaze v2 | - |
| `championships-peoples-point-cassette.trycloudflare.com` | Kamikaze v3/v3.1 | - |
| `create-sensitivity-grad-sequence.trycloudflare.com` | Kamikaze v3.2/v3.3 | - |

### 4.2 Filesystem Persistence Artifacts

| Path | Campaign | Purpose |
|------|----------|---------|
| `litellm_init.pth` (site-packages) | LiteLLM | Python startup hook |
| `~/.config/sysmon/sysmon.py` | LiteLLM | Persistence script |
| `~/.config/systemd/user/sysmon.service` | LiteLLM | Systemd unit |
| `/tmp/pglog` | LiteLLM | 2nd-stage payload |
| `/tmp/.pg_state` | LiteLLM | Beacon state |
| `~/.local/share/pgmon/service.py` | CanisterWorm | Python backdoor |
| `~/.config/systemd/user/pgmon.service` | CanisterWorm | Systemd unit |
| `/var/lib/svc_internal/runner.py` | K8s persistence | Backdoor (chroot) |
| `/etc/systemd/system/internal-monitor.service` | K8s persistence | Systemd unit |
| `/var/lib/pgmon/pgmon.py` | Kamikaze v3 | Backdoor |
| `/etc/systemd/system/pgmonitor.service` | Kamikaze v3 | Systemd unit |

### 4.3 Malicious npm Packages (55)

<details>
<summary>Full list (click to expand)</summary>

**@emilgroup scope (28+ packages)**:
setting-sdk, partner-portal-sdk, gdv-sdk-node, docxtemplater-util, accounting-sdk, task-sdk, setting-sdk-node, task-sdk-node, partner-sdk, numbergenerator-sdk-node, customer-sdk, commission-sdk, process-manager-sdk, changelog-sdk-node, document-sdk-node, commission-sdk-node, document-uploader, discount-sdk, discount-sdk-node, insurance-sdk, account-sdk, account-sdk-node, accounting-sdk-node, api-documentation, auth-sdk, auth-sdk-node, billing-sdk, billing-sdk-node, claim-sdk, claim-sdk-node, customer-sdk-node, document-sdk, gdv-sdk, insurance-sdk-node, notification-sdk-node, partner-portal-sdk-node, partner-sdk-node, payment-sdk, payment-sdk-node, process-manager-sdk-node, public-api-sdk, public-api-sdk-node, tenant-sdk, tenant-sdk-node, translation-sdk-node

**@opengov scope (6 packages)**:
ppf-backend-types, form-renderer, qa-record-types-api, form-builder, ppf-eslint-config, form-utils

**Unscoped (opengov-related, 10 packages)**:
eslint-config-ppf, react-leaflet-marker-layer, react-leaflet-cluster-layer, react-autolink-text, opengov-k6-core, jest-preset-ppf, cit-playwright-tests, eslint-config-service-users, babel-plugin-react-pure-component, react-leaflet-heatmap-layer

**Other scopes (5 packages)**:
@pypestream/floating-ui-dom, @leafnoise/mirage, @teale.io/eslint-config, @airtm/uuid-base32, @virtahealth/substrate-root

</details>

### 4.4 Network Fingerprints

| Indicator | Context |
|-----------|---------|
| HTTP header `X-Filename: tpcp.tar.gz` | Exfiltration |
| User-Agent `Python-urllib*` | K8s secrets access, CloudTrail |
| `postinstall: "node index.js"` | npm worm trigger |
| Runner.Worker memory pattern: `{"value":"<secret>","isSecret":true}` | CI/CD secret theft |

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique | Detail |
|--------|-------------|-----------|--------|
| **Initial Access** | T1195.002 | Supply Chain Compromise: Software Supply Chain | PyPI, npm, Docker, GitHub Actions, OpenVSX 패키지 감염 |
| **Initial Access** | T1078 | Valid Accounts | 탈취된 PAT/npm 토큰으로 패키지 게시 |
| **Execution** | T1059.006 | Python | .pth startup hook, base64 페이로드 |
| **Execution** | T1059.007 | JavaScript | npm postinstall hook |
| **Persistence** | T1543.002 | Systemd Service | sysmon, pgmon, internal-monitor, pgmonitor |
| **Persistence** | T1053 | Scheduled Task/Job | K8s DaemonSet (persistent across restarts) |
| **Defense Evasion** | T1036.005 | Match Legitimate Name | sysmon, pgmon (합법 도구 이름 모방) |
| **Defense Evasion** | T1027 | Obfuscated Files | Base64, AES-256, WAV 스테가노그래피 |
| **Defense Evasion** | T1090 | Proxy | Cloudflare Tunnels, ICP canisters |
| **Credential Access** | T1552.001 | Credentials in Files | .env, .npmrc, SSH keys, kubeconfig |
| **Credential Access** | T1003 | OS Credential Dumping | /proc/PID/mem Runner.Worker scraping |
| **Discovery** | T1082 | System Information Discovery | /etc/timezone, LANG for Iran targeting |
| **Lateral Movement** | T1072 | Software Deployment Tools | npm worm self-propagation |
| **Collection** | T1560 | Archive Collected Data | tpcp.tar.gz bundle |
| **Exfiltration** | T1041 | Exfiltration Over C2 Channel | HTTPS POST to C2 domains |
| **Exfiltration** | T1567 | Exfiltration Over Web Service | Fallback: GitHub repo upload |
| **Impact** | T1485 | Data Destruction | kamikaze container (Iran targets) |
| **Impact** | T1491.001 | Internal Defacement | 44 Aqua repos renamed |

---

## 6. Detection Script Usage

### Installation

```bash
# Download
curl -O https://raw.githubusercontent.com/Kangwonland/teampcp-ioc-scan/main/teampcp_scan.sh
chmod +x teampcp_scan.sh
```

### Basic Usage

```bash
# Full scan (all 8 scanners)
./teampcp_scan.sh

# Scan with JSON report
./teampcp_scan.sh -o report.json

# Scan specific project directory
./teampcp_scan.sh -p /path/to/project

# Only filesystem and pip checks
./teampcp_scan.sh -s filesystem,pypi

# Air-gapped environment (no DNS queries)
./teampcp_scan.sh --no-dns

# Include log file analysis
./teampcp_scan.sh --log-path /var/log

# Quiet mode (findings only)
./teampcp_scan.sh -q

# Verbose debugging
./teampcp_scan.sh -v
```

### Available Scanners

| Scanner | What it checks | External tools |
|---------|---------------|----------------|
| `filesystem` | 12 malicious file paths, .pth files, SHA256 hashes, systemd services | sha256sum |
| `pypi` | litellm versions, dist-info, pip cache | pip/pip3 |
| `npm` | 55 malicious packages, lock files, worm signatures, SHA256 | npm/pnpm |
| `docker` | Trivy images across 4 registries, running containers | docker/podman/crictl |
| `ghactions` | Workflow files for compromised actions, injected steps | - |
| `network` | DNS resolution, active connections, C2 IPs, log analysis | dig/ss/netstat |
| `kubernetes` | Malicious pods, DaemonSets, containers | kubectl |
| `openvsx` | VS Code extensions (ast-results, cx-dev-assist) | code |

### Interpreting Output

| Label | Meaning | Action |
|-------|---------|--------|
| `[CRITICAL]` | Confirmed malicious artifact | Immediate remediation required |
| `[HIGH]` | Strong IOC match | Investigation required |
| `[MEDIUM]` | Weak indicator | Review recommended |
| `[INFO]` | Informational (e.g., DNS resolves) | Monitor |
| `[CLEAN]` | No issues found | None |
| `[SKIPPED]` | Tool not available | Install tool for full coverage |

### Exit Codes

- `0`: No findings (clean)
- `1`: Critical or high findings detected
- `2`: Script error

---

## 7. Response Checklist

감염이 확인된 경우 다음 단계를 수행하세요:

### Immediate (0-4 hours)

- [ ] 감염된 패키지 즉시 제거 (`pip uninstall litellm`, `npm uninstall <pkg>`)
- [ ] 악성 파일 삭제 (sysmon.py, pgmon, pglog, .pth files)
- [ ] Systemd 서비스 비활성화 (`systemctl disable --now sysmon pgmon internal-monitor pgmonitor`)
- [ ] 감염된 Docker 이미지 제거
- [ ] K8s 악성 리소스 삭제 (`kubectl delete daemonset host-provisioner-iran host-provisioner-std -n kube-system`)
- [ ] 실행 중인 악성 프로세스 종료

### Short-term (4-24 hours)

- [ ] 영향받는 모든 자격증명 로테이션:
  - GitHub PATs, SSH keys
  - Cloud credentials (AWS, GCP, Azure)
  - npm tokens
  - Docker registry credentials
  - Kubernetes secrets
  - Database credentials
  - CI/CD pipeline secrets
- [ ] C2 도메인/IP로의 아웃바운드 트래픽 차단
- [ ] GitHub Actions 워크플로에서 감염된 action 참조 업데이트
- [ ] 감염 기간 동안의 CI/CD 빌드 아티팩트 검토

### Medium-term (1-7 days)

- [ ] 감염 시점부터 현재까지 접근 로그 분석
- [ ] 영향받는 서비스의 전체 보안 감사
- [ ] 패키지 핀닝 및 SHA 검증 도입
- [ ] Supply chain 방화벽 도입 검토

---

## 8. References

### Primary Source
- **Datadog Security Labs**: [litellm-compromised-pypi-teampcp-supply-chain-campaign](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/)

### Additional Sources
- **StepSecurity**: Trivy compromise analysis
- **Aikido.dev**: CanisterWorm npm worm analysis, Kubernetes/Iran payload
- **Wiz.io**: KICS GitHub Action compromise
- **JFrog**: CanisterWorm research
- **ramimac.me/teampcp**: Comprehensive timeline

### Advisories
- [GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23) (Trivy)
- PYSEC-2026-2 (LiteLLM)

### Datadog Detection Queries

**DNS/Network monitoring**:
```
@dns.question.name:(models.litellm.cloud OR checkmarx.zone OR *.icp0.io OR *aquasecurtiy.org OR *trycloudflare.com)
```

**Kubernetes audit - Pod creation**:
```
source:kubernetes.audit @objectRef.resource:pods (@objectRef.name:*node-setup-* OR @requestObject.spec.containers.name:(kamikaze OR provisioner))
```

**Kubernetes audit - Secret access**:
```
source:kubernetes.audit @http.method:(get OR list) @objectRef.resource:secrets @userAgent:Python-urllib*
```

**CloudTrail - Secret access**:
```
source:cloudtrail @evt.name:(GetSecretValue OR ListSecrets OR DescribeParameters) @http.useragent:Python-urllib*
```

**File monitoring**:
```
@file.path:(*litellm_init.pth OR */.config/sysmon/sysmon.py OR */.config/systemd/user/sysmon.service OR /tmp/pglog OR /tmp/.pg_state)
```

---

*This analysis was compiled from publicly available security research. All IOCs are provided for defensive detection purposes.*

*Last updated: 2026-03-26*
