#!/usr/bin/env bash
# =============================================================================
# TeamPCP Supply Chain IOC Scanner v1.0
# Campaign: March 19-24, 2026
#
# Detects indicators of compromise from the TeamPCP multi-ecosystem
# supply chain attack across PyPI, npm, GitHub Actions, Docker, and OpenVSX.
#
# Usage: ./teampcp_scan.sh [OPTIONS]
# Dependencies: bash, grep, find, awk (all standard Linux)
# Optional: pip, npm, docker, kubectl, dig, ss, code
# =============================================================================

set +e  # Don't exit on individual command failures
VERSION="1.0.0"

# =============================================================================
# COLOR CONSTANTS
# =============================================================================
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED='\033[0;31m'
    RED_BG='\033[41;97m'
    YELLOW='\033[0;33m'
    GREEN='\033[0;32m'
    CYAN='\033[0;36m'
    DIM='\033[2m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' RED_BG='' YELLOW='' GREEN='' CYAN='' DIM='' BOLD='' RESET=''
fi

# =============================================================================
# IOC DATA
# =============================================================================

# C2 Domains
C2_DOMAINS=(
    "models.litellm.cloud"
    "litellm.cloud"
    "checkmarx.zone"
    "scan.aquasecurtiy.org"
    "aquasecurtiy.org"
    "tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io"
    "souls-entire-defined-routes.trycloudflare.com"
    "plug-tab-protective-relay.trycloudflare.com"
    "investigation-launches-hearings-copying.trycloudflare.com"
    "championships-peoples-point-cassette.trycloudflare.com"
    "create-sensitivity-grad-sequence.trycloudflare.com"
)

# Known C2 IPs
C2_IPS=("45.148.10.212" "83.142.209.11")

# Malicious file paths (use $HOME at runtime)
MALICIOUS_FILES_RELATIVE=(
    ".config/sysmon/sysmon.py"
    ".config/systemd/user/sysmon.service"
    ".local/share/pgmon/service.py"
    ".config/systemd/user/pgmon.service"
)
MALICIOUS_FILES_ABSOLUTE=(
    "/tmp/pglog"
    "/tmp/.pg_state"
    "/var/lib/svc_internal/runner.py"
    "/etc/systemd/system/internal-monitor.service"
    "/var/lib/pgmon/pgmon.py"
    "/etc/systemd/system/pgmonitor.service"
)

# Systemd service names
SYSTEMD_SERVICES=("sysmon" "pgmon" "internal-monitor" "pgmonitor")

# SHA256 hashes - malicious files
declare -A FILE_HASHES=(
    ["litellm_init.pth"]="71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238"
    ["proxy_server.py"]="a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b"
)

# SHA256 hashes - npm worm index.js
NPM_WORM_INDEX_HASHES=(
    "e9b1e069efc778c1e77fb3f5fcc3bd3580bbc810604cbf4347897ddb4b8c163b"
    "61ff00a81b19624adaad425b9129ba2f312f4ab76fb5ddc2c628a5037d31a4ba"
    "0c0d206d5e68c0cf64d57ffa8bc5b1dad54f2dda52f24e96e02e237498cb9c3a"
    "c37c0ae9641d2e5329fcdee847a756bf1140fdb7f0b7c78a40fdc39055e7d926"
)

# SHA256 hashes - npm worm deploy.js
NPM_WORM_DEPLOY_HASHES=(
    "f398f06eefcd3558c38820a397e3193856e4e6e7c67f81ecc8e533275284b152"
    "7df6cef7ab9aae2ea08f2f872f6456b5d51d896ddda907a238cd6668ccdc4bb7"
    "5e2ba7c4c53fa6e0cef58011acdd50682cf83fb7b989712d2fcf1b5173bad956"
)

# Docker image SHAs
declare -A DOCKER_IMAGE_SHAS=(
    ["aquasec/trivy:0.69.5"]="f69a8a4180c43fc427532ddde34a256acbd041a0a07844cf7e4d3e0434e5bcd1"
    ["aquasec/trivy:0.69.6"]="dd8beb3b40df080b3fd7f9a0f5a1b02f3692f65c68980f46da8328ce8bb788ef"
)

# Malicious Docker images
DOCKER_MALICIOUS_REPOS=(
    "aquasec/trivy"
    "ghcr.io/aquasecurity/trivy"
    "public.ecr.aws/aquasecurity/trivy"
    "mirror.gcr.io/aquasec/trivy"
)
DOCKER_MALICIOUS_TAGS=("0.69.4" "0.69.5" "0.69.6")

# Malicious GitHub Actions - known malicious commit SHAs (partial, for prefix matching)
MALICIOUS_ACTION_SHAS=("70379aad1a8b" "1885610c6a34" "8afa9b9f9183" "ddb9da4475c1")

# Malicious npm scoped packages (scope names for broad matching)
NPM_MALICIOUS_SCOPES=("@emilgroup" "@opengov")

# Malicious npm packages - unscoped and other scopes (name:version)
NPM_MALICIOUS_PACKAGES=(
    "@pypestream/floating-ui-dom:2.15.1"
    "@leafnoise/mirage:2.0.3"
    "@airtm/uuid-base32:1.0.2"
    "@virtahealth/substrate-root:1.0.1"
    "eslint-config-ppf:0.128.2"
    "react-leaflet-marker-layer:0.1.5"
    "react-leaflet-cluster-layer:0.0.4"
    "react-autolink-text:2.0.1"
    "opengov-k6-core:1.0.2"
    "jest-preset-ppf:0.0.2"
    "cit-playwright-tests:1.0.1"
    "eslint-config-service-users:0.0.3"
    "babel-plugin-react-pure-component:0.1.6"
    "react-leaflet-heatmap-layer:2.0.1"
)

# @teale.io/eslint-config malicious versions
# TODO: Implement version-specific checking for @teale.io/eslint-config in npm scanner
TEALE_MALICIOUS_VERSIONS=("1.8.9" "1.8.10" "1.8.11" "1.8.12" "1.8.13" "1.8.14" "1.8.15" "1.8.16")

# Attribution strings to search for
ATTRIBUTION_STRINGS=("TeamPCP" "tpcp.tar.gz" "tpcp-docs" "docs-tpcp" "TeamPCP Cloud stealer" "TeamPCP Owns Aqua Security")

# C2 content signatures (for file content grep)
C2_CONTENT_SIGNATURES=("models.litellm.cloud" "checkmarx.zone" "scan.aquasecurtiy.org" "aquasecurtiy.org" "icp0.io" "trycloudflare.com" "tpcp.tar.gz")

# npm worm function signatures
NPM_WORM_FUNCTIONS=("findNpmTokens" "bumpPatch" "getOwnedPackages" "deployWithToken")

# =============================================================================
# GLOBAL COUNTERS & STATE
# =============================================================================
TOTAL_CRITICAL=0
TOTAL_HIGH=0
TOTAL_MEDIUM=0
TOTAL_INFO=0
SCAN_START=""
JSON_FINDINGS=""
JSON_SCANNER_RESULTS=""
SCAN_PATH="${HOME}"
JSON_OUTPUT=""
SCANNERS_TO_RUN="all"
NO_DNS=0
VERBOSE=0
QUIET=0
LOG_PATH=""

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

cmd_exists() { command -v "$1" >/dev/null 2>&1; }

json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' | tr '\n' ' '
}

compute_sha256() {
    local file="$1"
    if cmd_exists sha256sum; then
        sha256sum "$file" 2>/dev/null | awk '{print $1}'
    elif cmd_exists shasum; then
        shasum -a 256 "$file" 2>/dev/null | awk '{print $1}'
    else
        echo "NO_HASH_TOOL"
    fi
}

log_critical() {
    ((TOTAL_CRITICAL++))
    printf "  ${RED_BG}[CRITICAL]${RESET} %s\n" "$1"
    [ -n "$2" ] && printf "             ${RED}-> %s${RESET}\n" "$2"
    [ -n "$3" ] && printf "             ${YELLOW}-> Remediation: %s${RESET}\n" "$3"
}

log_high() {
    ((TOTAL_HIGH++))
    printf "  ${RED}[HIGH]${RESET} %s\n" "$1"
    [ -n "$2" ] && printf "         ${RED}-> %s${RESET}\n" "$2"
    [ -n "$3" ] && printf "         ${YELLOW}-> Remediation: %s${RESET}\n" "$3"
}

log_medium() {
    ((TOTAL_MEDIUM++))
    printf "  ${YELLOW}[MEDIUM]${RESET} %s\n" "$1"
    [ -n "$2" ] && printf "           ${YELLOW}-> %s${RESET}\n" "$2"
}

log_info() {
    ((TOTAL_INFO++))
    printf "  ${CYAN}[INFO]${RESET} %s\n" "$1"
    [ -n "$2" ] && printf "         ${CYAN}-> %s${RESET}\n" "$2"
}

log_clean() {
    [ "$QUIET" -eq 1 ] && return
    printf "  ${GREEN}[CLEAN]${RESET} %s\n" "$1"
}

log_skip() {
    [ "$QUIET" -eq 1 ] && return
    printf "  ${DIM}[SKIPPED]${RESET} %s\n" "$1"
}

log_verbose() {
    [ "$VERBOSE" -eq 1 ] && printf "  ${DIM}[DEBUG]${RESET} %s\n" "$1"
}

print_section() {
    [ "$QUIET" -eq 1 ] && return
    printf "\n${BOLD}[SCAN]${RESET} %s\n" "$1"
}

add_json_finding() {
    local scanner="$1" severity="$2" title="$3" details="$4" remediation="$5"
    local escaped_title escaped_details escaped_remediation
    escaped_title=$(json_escape "$title")
    escaped_details=$(json_escape "$details")
    escaped_remediation=$(json_escape "$remediation")
    local entry
    entry=$(printf '{"scanner":"%s","severity":"%s","title":"%s","details":"%s","remediation":"%s"}' \
        "$scanner" "$severity" "$escaped_title" "$escaped_details" "$escaped_remediation")
    if [ -z "$JSON_FINDINGS" ]; then
        JSON_FINDINGS="$entry"
    else
        JSON_FINDINGS="${JSON_FINDINGS},${entry}"
    fi
}

add_json_scanner_result() {
    local scanner="$1" status="$2" duration="$3" findings="$4" reason="$5"
    local entry
    if [ -n "$reason" ]; then
        local escaped_reason
        escaped_reason=$(json_escape "$reason")
        entry=$(printf '{"scanner":"%s","status":"%s","duration_sec":%s,"findings_count":%s,"reason":"%s"}' \
            "$scanner" "$status" "$duration" "$findings" "$escaped_reason")
    else
        entry=$(printf '{"scanner":"%s","status":"%s","duration_sec":%s,"findings_count":%s}' \
            "$scanner" "$status" "$duration" "$findings")
    fi
    if [ -z "$JSON_SCANNER_RESULTS" ]; then
        JSON_SCANNER_RESULTS="$entry"
    else
        JSON_SCANNER_RESULTS="${JSON_SCANNER_RESULTS},${entry}"
    fi
}

should_run_scanner() {
    local name="$1"
    [ "$SCANNERS_TO_RUN" = "all" ] && return 0
    echo ",$SCANNERS_TO_RUN," | command grep -q ",$name," && return 0
    return 1
}

check_file_for_c2() {
    local file="$1"
    # Skip this scanner script itself to avoid self-detection
    local script_real file_real
    script_real=$(realpath "${BASH_SOURCE[0]}" 2>/dev/null) || script_real="${BASH_SOURCE[0]}"
    file_real=$(realpath "$file" 2>/dev/null) || file_real="$file"
    [ "$file_real" = "$script_real" ] && return 1
    for sig in "${C2_CONTENT_SIGNATURES[@]}"; do
        if command grep -q "$sig" "$file" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

# =============================================================================
# SCANNER 1: FILESYSTEM
# =============================================================================
scan_filesystem() {
    print_section "Filesystem artifacts..."
    local start_time findings=0
    start_time=$(date +%s)

    # Check known malicious file paths (relative to HOME)
    for relpath in "${MALICIOUS_FILES_RELATIVE[@]}"; do
        local fullpath="${HOME}/${relpath}"
        if [ -f "$fullpath" ]; then
            if check_file_for_c2 "$fullpath"; then
                log_critical "Found $fullpath" "Contains C2 domain references - confirmed malicious" "Delete: rm -f '$fullpath'"
                add_json_finding "filesystem" "critical" "Malicious file: $fullpath" "Contains C2 signatures" "rm -f $fullpath"
                ((findings++))
            else
                log_high "Found suspicious file: $fullpath" "Path matches known TeamPCP persistence artifact" "Inspect contents and delete if unauthorized"
                add_json_finding "filesystem" "high" "Suspicious file: $fullpath" "Path matches IOC but no C2 signatures" "Inspect and remove"
                ((findings++))
            fi
            [ -L "$fullpath" ] && log_info "  (symlink -> $(readlink -f "$fullpath"))"
        fi
    done

    # Check absolute paths
    for abspath in "${MALICIOUS_FILES_ABSOLUTE[@]}"; do
        if [ -f "$abspath" ]; then
            if check_file_for_c2 "$abspath"; then
                log_critical "Found $abspath" "Contains C2 domain references - confirmed malicious" "Delete: rm -f '$abspath'"
                add_json_finding "filesystem" "critical" "Malicious file: $abspath" "Contains C2 signatures" "rm -f $abspath"
            else
                log_high "Found suspicious file: $abspath" "Path matches known TeamPCP artifact" "Inspect contents"
                add_json_finding "filesystem" "high" "Suspicious file: $abspath" "Path matches IOC" "Inspect and remove"
            fi
            ((findings++))
        fi
    done

    # Search for litellm_init.pth in all Python site-packages
    log_verbose "Searching for litellm_init.pth in site-packages..."
    local pth_found=0
    local search_dirs=(/usr/lib/python3* /usr/local/lib/python3* "${HOME}/.local/lib/python3*")
    # Add conda/venv paths
    for d in "${HOME}/miniconda3" "${HOME}/anaconda3" "${HOME}/mambaforge" "${HOME}/.conda"; do
        [ -d "$d" ] && search_dirs+=("$d")
    done

    while IFS= read -r pth_file; do
        [ -z "$pth_file" ] && continue
        local hash
        hash=$(compute_sha256 "$pth_file")
        if [ "$hash" = "NO_HASH_TOOL" ]; then
            log_medium "Cannot verify hash (no sha256sum/shasum): $pth_file" "Install sha256sum for verification"
            add_json_finding "filesystem" "medium" "Unverified litellm_init.pth" "No hash tool at $pth_file" "Install sha256sum"
        elif [ "$hash" = "${FILE_HASHES[litellm_init.pth]}" ]; then
            log_critical "Found malicious litellm_init.pth: $pth_file" "SHA256 matches known malicious hash" "Delete immediately: rm -f '$pth_file'"
            add_json_finding "filesystem" "critical" "Malicious litellm_init.pth" "SHA256: $hash at $pth_file" "rm -f $pth_file"
        else
            log_high "Found litellm_init.pth: $pth_file" "SHA256: $hash (unknown hash - inspect manually)" "Verify this is not a malicious .pth file"
            add_json_finding "filesystem" "high" "Suspicious litellm_init.pth" "SHA256: $hash at $pth_file" "Inspect manually"
        fi
        ((findings++))
        pth_found=1
    done < <(find "${search_dirs[@]}" -name "litellm_init.pth" 2>/dev/null)

    # Also search in SCAN_PATH for venvs
    if [ "$SCAN_PATH" != "$HOME" ]; then
        while IFS= read -r pth_file; do
            [ -z "$pth_file" ] && continue
            local hash
            hash=$(compute_sha256 "$pth_file")
            if [ "$hash" = "NO_HASH_TOOL" ]; then
                log_medium "Cannot verify hash (no sha256sum/shasum): $pth_file" "Install sha256sum for verification"
                add_json_finding "filesystem" "medium" "Unverified litellm_init.pth" "No hash tool at $pth_file" "Install sha256sum"
            elif [ "$hash" = "${FILE_HASHES[litellm_init.pth]}" ]; then
                log_critical "Found malicious litellm_init.pth in venv: $pth_file" "SHA256 matches known malicious hash" "Delete: rm -f '$pth_file'"
                add_json_finding "filesystem" "critical" "Malicious litellm_init.pth" "SHA256: $hash at $pth_file" "rm -f $pth_file"
            else
                log_high "Found litellm_init.pth in venv: $pth_file" "SHA256: $hash (unknown - inspect manually)" "Verify this is not a malicious .pth file"
                add_json_finding "filesystem" "high" "Suspicious litellm_init.pth in venv" "SHA256: $hash at $pth_file" "Inspect manually"
            fi
            ((findings++))
            pth_found=1
        done < <(timeout 30 find "$SCAN_PATH" -path "*/site-packages/litellm_init.pth" 2>/dev/null)
    fi

    [ "$pth_found" -eq 0 ] && log_clean "No malicious .pth files found"

    # Check for malicious proxy_server.py
    log_verbose "Checking litellm/proxy/proxy_server.py hashes..."
    local proxy_found=0
    while IFS= read -r proxy_file; do
        [ -z "$proxy_file" ] && continue
        local hash
        hash=$(compute_sha256 "$proxy_file")
        if [ "$hash" = "NO_HASH_TOOL" ]; then
            log_medium "Cannot verify proxy_server.py hash: $proxy_file" "Install sha256sum for verification"
            add_json_finding "filesystem" "medium" "Unverified proxy_server.py" "No hash tool at $proxy_file" "Install sha256sum"
        elif [ "$hash" = "${FILE_HASHES[proxy_server.py]}" ]; then
            log_critical "Found malicious proxy_server.py: $proxy_file" "SHA256 matches litellm 1.82.7 injected payload" "Upgrade litellm immediately"
            add_json_finding "filesystem" "critical" "Malicious proxy_server.py" "SHA256 match at $proxy_file" "pip install --upgrade litellm"
            ((findings++))
            proxy_found=1
        fi
    done < <(find "${search_dirs[@]}" -path "*/litellm/proxy/proxy_server.py" 2>/dev/null)

    [ "$proxy_found" -eq 0 ] && log_clean "No malicious proxy_server.py found"

    # Check systemd services
    log_verbose "Checking systemd services..."
    local svc_found=0
    for svc in "${SYSTEMD_SERVICES[@]}"; do
        if systemctl list-unit-files 2>/dev/null | command grep -q "${svc}\.service"; then
            log_high "Systemd service '${svc}.service' exists" "Matches TeamPCP persistence service name" "systemctl disable --now ${svc} && rm unit file"
            add_json_finding "filesystem" "high" "Suspicious systemd service: ${svc}" "Matches TeamPCP IOC" "systemctl disable --now ${svc}"
            ((findings++))
            svc_found=1
        fi
        # Also check user services
        if [ -f "${HOME}/.config/systemd/user/${svc}.service" ]; then
            log_high "User systemd service found: ${svc}.service" "In ~/.config/systemd/user/" "Remove and run: systemctl --user daemon-reload"
            add_json_finding "filesystem" "high" "User systemd service: ${svc}" "In ~/.config/systemd/user/" "Remove and daemon-reload"
            ((findings++))
            svc_found=1
        fi
    done
    [ "$svc_found" -eq 0 ] && log_clean "No suspicious systemd services"

    # Check for container environment
    if [ -f "/.dockerenv" ] || command grep -q "docker\|containerd" /proc/1/cgroup 2>/dev/null; then
        log_info "Running inside a container" "Some host-level checks may be incomplete"
    fi

    local duration=$(( $(date +%s) - start_time ))
    add_json_scanner_result "filesystem" "$([ "$findings" -gt 0 ] && echo found || echo clean)" "$duration" "$findings"
}

# =============================================================================
# SCANNER 2: PYPI
# =============================================================================
scan_pypi() {
    print_section "Python packages (pip)..."
    local start_time findings=0
    start_time=$(date +%s)

    local litellm_found=0

    # Method 1: Try pip list commands
    for pip_cmd in "pip" "pip3" "python3 -m pip" "python -m pip"; do
        if $pip_cmd --version >/dev/null 2>&1; then
            log_verbose "Checking via: $pip_cmd list"
            local version
            version=$($pip_cmd list --format=columns 2>/dev/null | command grep -i "^litellm " | awk '{print $2}')
            if [ -n "$version" ]; then
                if [ "$version" = "1.82.7" ] || [ "$version" = "1.82.8" ]; then
                    log_critical "litellm $version installed (via $pip_cmd)" "Known malicious version from TeamPCP campaign" "pip uninstall litellm && pip install litellm>=1.82.9"
                    add_json_finding "pypi" "critical" "Malicious litellm $version" "Detected via $pip_cmd" "pip uninstall litellm && pip install litellm>=1.82.9"
                    ((findings++))
                    litellm_found=1
                else
                    log_clean "litellm $version installed (safe version)"
                    litellm_found=1
                fi
            fi
        fi
    done

    # Method 2: Search dist-info directories directly
    log_verbose "Searching for litellm dist-info in site-packages..."
    while IFS= read -r dist_dir; do
        [ -z "$dist_dir" ] && continue
        local dirname
        dirname=$(basename "$dist_dir")
        if echo "$dirname" | command grep -qE "litellm-1\.82\.(7|8)\.dist-info"; then
            log_critical "Found malicious litellm dist-info: $dist_dir" "Version 1.82.7 or 1.82.8 installed" "Remove package and dist-info directory"
            add_json_finding "pypi" "critical" "Malicious litellm dist-info" "$dist_dir" "pip uninstall litellm"
            ((findings++))
            litellm_found=1
        fi
    done < <(find /usr/lib/python3* /usr/local/lib/python3* "${HOME}/.local/lib" "${HOME}/miniconda3" "${HOME}/anaconda3" \
        -name "litellm-*.dist-info" -type d 2>/dev/null)

    # Method 3: Check pip cache for malicious wheels/tarballs
    log_verbose "Checking pip cache..."
    local cache_dirs=("${HOME}/.cache/pip" "/tmp/pip-*")
    for cache_dir in "${cache_dirs[@]}"; do
        while IFS= read -r cached; do
            [ -z "$cached" ] && continue
            local hash
            hash=$(compute_sha256 "$cached")
            [ "$hash" = "NO_HASH_TOOL" ] && continue
            case "$hash" in
                "8395c3268d5c5dbae1c7c6d4bb3c318c752ba4608cfcd90eb97ffb94a910eac2"|\
                "d2a0d5f564628773b6af7b9c11f6b86531a875bd2d186d7081ab62748a800ebb"|\
                "8a2a05fd8bdc329c8a86d2d08229d167500c01ecad06e40477c49fb0096efdea"|\
                "d39f4e7a218053cce976c91eacf184cf09a6960c731cc9d66d8e1a53406593a5")
                    log_high "Malicious litellm package in pip cache: $cached" "SHA256: $hash" "rm -rf ${HOME}/.cache/pip"
                    add_json_finding "pypi" "high" "Cached malicious litellm" "SHA256: $hash at $cached" "Clear pip cache"
                    ((findings++))
                    ;;
            esac
        done < <(find $cache_dir -name "litellm-1.82.*" 2>/dev/null)
    done

    if [ "$litellm_found" -eq 0 ] && [ "$findings" -eq 0 ]; then
        log_clean "litellm not installed or safe version"
    fi

    local duration=$(( $(date +%s) - start_time ))
    add_json_scanner_result "pypi" "$([ "$findings" -gt 0 ] && echo found || echo clean)" "$duration" "$findings"
}

# =============================================================================
# SCANNER 3: NPM
# =============================================================================
scan_npm() {
    print_section "npm packages..."
    local start_time findings=0
    start_time=$(date +%s)

    # Build grep pattern for all malicious package names
    local npm_pattern=""
    # Scoped packages
    for scope in "${NPM_MALICIOUS_SCOPES[@]}"; do
        if [ -z "$npm_pattern" ]; then
            npm_pattern="\"${scope}/"
        else
            npm_pattern="${npm_pattern}|\"${scope}/"
        fi
    done
    # Specific packages
    for pkg_ver in "${NPM_MALICIOUS_PACKAGES[@]}"; do
        local pkg="${pkg_ver%%:*}"
        npm_pattern="${npm_pattern}|\"${pkg}\""
    done
    npm_pattern="${npm_pattern}|\"@teale.io/eslint-config\""

    # Method 1: Check global npm packages
    if cmd_exists npm; then
        log_verbose "Checking global npm packages..."
        local npm_global
        npm_global=$(npm ls -g --depth=0 --json 2>/dev/null)
        if [ -n "$npm_global" ]; then
            for scope in "${NPM_MALICIOUS_SCOPES[@]}"; do
                local scope_matches
                scope_matches=$(echo "$npm_global" | command grep -o "\"${scope}/[^\"]*\"" 2>/dev/null)
                if [ -n "$scope_matches" ]; then
                    log_critical "Global npm packages from malicious scope ${scope} found" "$scope_matches" "npm uninstall -g <package>"
                    add_json_finding "npm" "critical" "Malicious scope $scope in global" "$scope_matches" "npm uninstall -g"
                    ((findings++))
                fi
            done
        fi
    elif cmd_exists pnpm; then
        log_verbose "npm not found, trying pnpm..."
        pnpm ls -g --json 2>/dev/null | command grep -E "$npm_pattern" && {
            log_high "Potentially malicious packages found via pnpm global" "" "Inspect and remove"
            add_json_finding "npm" "high" "Malicious packages via pnpm" "Global pnpm packages match IOC" "Inspect and remove"
            ((findings++))
        }
    else
        log_skip "npm/pnpm not installed - checking filesystem directly"
    fi

    # Method 2: Scan lock files for malicious package names
    log_verbose "Scanning lock files in $SCAN_PATH..."
    local lock_findings=0
    while IFS= read -r lockfile; do
        [ -z "$lockfile" ] && continue
        log_verbose "Checking: $lockfile"
        local matches
        matches=$(command grep -nE "$npm_pattern" "$lockfile" 2>/dev/null | head -20)
        if [ -n "$matches" ]; then
            log_critical "Malicious package reference in: $lockfile" "$(echo "$matches" | head -5)" "Review and remove affected packages, regenerate lockfile"
            add_json_finding "npm" "critical" "Malicious package in lockfile" "$lockfile" "Remove and regenerate lockfile"
            ((findings++))
            ((lock_findings++))
        fi
    done < <(timeout 60 find "$SCAN_PATH" \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) \
        -not -path "*/node_modules/*" 2>/dev/null | head -100)

    [ "$lock_findings" -eq 0 ] && log_clean "No malicious packages in lock files"

    # Method 3: Check for npm worm indicators in node_modules
    log_verbose "Scanning node_modules for worm indicators..."
    local worm_found=0
    while IFS= read -r pkg_json; do
        [ -z "$pkg_json" ] && continue
        # Check for postinstall: "node index.js" pattern
        if command grep -q '"postinstall".*"node index.js"' "$pkg_json" 2>/dev/null; then
            local pkg_dir
            pkg_dir=$(dirname "$pkg_json")
            local pkg_name
            pkg_name=$(command grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg_json" 2>/dev/null | head -1 | sed 's/.*"name"[[:space:]]*:[[:space:]]*"//;s/"//')

            # Check if it's from a known malicious scope
            for scope in "${NPM_MALICIOUS_SCOPES[@]}"; do
                if echo "$pkg_name" | command grep -q "^${scope}/"; then
                    # Verify with hash check on index.js
                    if [ -f "${pkg_dir}/index.js" ]; then
                        local hash
                        hash=$(compute_sha256 "${pkg_dir}/index.js")
                        for known_hash in "${NPM_WORM_INDEX_HASHES[@]}"; do
                            if [ "$hash" = "$known_hash" ]; then
                                log_critical "CanisterWorm detected: $pkg_name ($pkg_dir)" "index.js SHA256 matches known worm variant" "rm -rf '$pkg_dir' and audit dependencies"
                                add_json_finding "npm" "critical" "CanisterWorm: $pkg_name" "SHA256: $hash" "rm -rf $pkg_dir"
                                ((findings++))
                                worm_found=1
                            fi
                        done
                    fi
                    break
                fi
            done

            # Check for deploy.js
            if [ -f "${pkg_dir}/deploy.js" ]; then
                local hash
                hash=$(compute_sha256 "${pkg_dir}/deploy.js")
                for known_hash in "${NPM_WORM_DEPLOY_HASHES[@]}"; do
                    if [ "$hash" = "$known_hash" ]; then
                        log_critical "CanisterWorm deploy.js detected: $pkg_dir" "SHA256 matches known worm" "Remove immediately"
                        add_json_finding "npm" "critical" "CanisterWorm deploy.js" "SHA256: $hash at $pkg_dir" "rm -rf $pkg_dir"
                        ((findings++))
                        worm_found=1
                    fi
                done
            fi
        fi
    done < <(timeout 60 find "$SCAN_PATH" -maxdepth 6 -path "*/node_modules/*/package.json" 2>/dev/null | head -500)

    # Method 4: Search for worm function signatures in JS files
    log_verbose "Searching for npm worm function signatures..."
    local func_pattern
    func_pattern=$(printf '%s|' "${NPM_WORM_FUNCTIONS[@]}" | sed 's/|$//')
    while IFS= read -r js_file; do
        [ -z "$js_file" ] && continue
        log_high "Worm function signatures found: $js_file" "Contains: findNpmTokens/bumpPatch/getOwnedPackages/deployWithToken" "Inspect and remove"
        add_json_finding "npm" "high" "Worm signatures in $js_file" "CanisterWorm function names detected" "Remove package"
        ((findings++))
    done < <(timeout 30 find "$SCAN_PATH" -path "*/node_modules/*" \( -name "index.js" -o -name "deploy.js" \) \
        -exec command grep -lE "$func_pattern" {} \; 2>/dev/null | head -20)

    # Also check .yarn/cache
    if [ -d "${SCAN_PATH}/.yarn/cache" ]; then
        log_verbose "Checking .yarn/cache..."
        for scope in "${NPM_MALICIOUS_SCOPES[@]}"; do
            local scope_dash="${scope//@/}"
            scope_dash="${scope_dash////-}"
            local found
            found=$(find "${SCAN_PATH}/.yarn/cache" -name "${scope_dash}-*" 2>/dev/null)
            if [ -n "$found" ]; then
                log_high "Potentially malicious yarn cache entries for $scope" "$found" "yarn cache clean"
                add_json_finding "npm" "high" "Malicious scope in yarn cache" "$scope: $found" "yarn cache clean"
                ((findings++))
            fi
        done
    fi

    local duration=$(( $(date +%s) - start_time ))
    add_json_scanner_result "npm" "$([ "$findings" -gt 0 ] && echo found || echo clean)" "$duration" "$findings"
}

# =============================================================================
# SCANNER 4: DOCKER
# =============================================================================
scan_docker() {
    print_section "Docker images..."
    local start_time findings=0
    start_time=$(date +%s)

    local docker_cmd=""
    if cmd_exists docker && docker info >/dev/null 2>&1; then
        docker_cmd="docker"
    elif cmd_exists podman; then
        docker_cmd="podman"
        log_verbose "Using podman instead of docker"
    elif cmd_exists crictl; then
        docker_cmd="crictl"
        log_verbose "Using crictl (containerd)"
    else
        log_skip "No container runtime found (docker/podman/crictl)"
        add_json_scanner_result "docker" "skipped" "0" "0" "No container runtime"
        return
    fi

    # Check local images
    log_verbose "Checking local images via $docker_cmd..."
    if [ "$docker_cmd" = "crictl" ]; then
        local images
        images=$(crictl images -o json 2>/dev/null)
        for repo in "${DOCKER_MALICIOUS_REPOS[@]}"; do
            for tag in "${DOCKER_MALICIOUS_TAGS[@]}"; do
                if echo "$images" | command grep -q "${repo}.*${tag}"; then
                    log_critical "Malicious image found: ${repo}:${tag}" "Known compromised Trivy image" "crictl rmi ${repo}:${tag}"
                    add_json_finding "docker" "critical" "Malicious image: ${repo}:${tag}" "Compromised Trivy" "Remove image"
                    ((findings++))
                fi
            done
        done
    else
        for repo in "${DOCKER_MALICIOUS_REPOS[@]}"; do
            for tag in "${DOCKER_MALICIOUS_TAGS[@]}"; do
                if $docker_cmd image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | command grep -q "^${repo}:${tag}$"; then
                    log_critical "Malicious image found: ${repo}:${tag}" "Known compromised Trivy image" "${docker_cmd} rmi ${repo}:${tag}"
                    add_json_finding "docker" "critical" "Malicious image: ${repo}:${tag}" "Compromised Trivy" "${docker_cmd} rmi ${repo}:${tag}"
                    ((findings++))
                fi
            done
        done

        # Check image digests against known malicious SHAs
        log_verbose "Checking image digests..."
        for image_tag in "${!DOCKER_IMAGE_SHAS[@]}"; do
            local expected_sha="${DOCKER_IMAGE_SHAS[$image_tag]}"
            local actual_digest
            actual_digest=$($docker_cmd image inspect "$image_tag" --format '{{.Id}}' 2>/dev/null | sed 's/sha256://')
            if [ -n "$actual_digest" ] && [ "$actual_digest" = "$expected_sha" ]; then
                log_critical "Image digest match: $image_tag" "SHA256: $expected_sha" "Remove image immediately"
                add_json_finding "docker" "critical" "Image SHA match: $image_tag" "SHA256: $expected_sha" "Remove image"
                ((findings++))
            fi
        done

        # Check running containers
        log_verbose "Checking running containers..."
        for repo in "${DOCKER_MALICIOUS_REPOS[@]}"; do
            for tag in "${DOCKER_MALICIOUS_TAGS[@]}"; do
                local running
                running=$($docker_cmd ps --format '{{.ID}} {{.Image}}' 2>/dev/null | command grep "${repo}:${tag}")
                if [ -n "$running" ]; then
                    local container_id
                    container_id=$(echo "$running" | awk '{print $1}')
                    log_critical "RUNNING container with malicious image: ${repo}:${tag}" "Container ID: $container_id" "${docker_cmd} stop $container_id && ${docker_cmd} rm $container_id"
                    add_json_finding "docker" "critical" "Running malicious container" "${repo}:${tag} (ID: $container_id)" "Stop and remove"
                    ((findings++))
                fi
            done
        done
    fi

    [ "$findings" -eq 0 ] && log_clean "No malicious container images found"

    local duration=$(( $(date +%s) - start_time ))
    add_json_scanner_result "docker" "$([ "$findings" -gt 0 ] && echo found || echo clean)" "$duration" "$findings"
}

# =============================================================================
# SCANNER 5: GITHUB ACTIONS
# =============================================================================
scan_github_actions() {
    print_section "GitHub Actions workflows..."
    local start_time findings=0
    start_time=$(date +%s)

    local workflow_count=0
    local workflow_files=()

    # Find all workflow files
    while IFS= read -r wf; do
        [ -z "$wf" ] && continue
        workflow_files+=("$wf")
        ((workflow_count++))
    done < <(timeout 30 find "$SCAN_PATH" \( -path "*/.github/workflows/*.yml" -o -path "*/.github/workflows/*.yaml" \) \
        -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | head -200)

    # Also check action.yml files (composite actions)
    while IFS= read -r af; do
        [ -z "$af" ] && continue
        workflow_files+=("$af")
    done < <(timeout 15 find "$SCAN_PATH" -name "action.yml" -path "*/.github/*" \
        -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | head -50)

    if [ ${#workflow_files[@]} -eq 0 ]; then
        log_skip "No GitHub Actions workflow files found in $SCAN_PATH"
        add_json_scanner_result "ghactions" "skipped" "0" "0" "No workflow files"
        return
    fi

    log_verbose "Found $workflow_count workflow files"

    for wf in "${workflow_files[@]}"; do
        # Extract all uses: lines
        while IFS= read -r uses_line; do
            [ -z "$uses_line" ] && continue
            local line_num action ref
            line_num=$(echo "$uses_line" | cut -d: -f1)
            # Parse action@ref
            local uses_value
            uses_value=$(echo "$uses_line" | sed -n 's/.*uses:[[:space:]]*["\x27]*\([^@"'\''[:space:]]*\)@\([^"'\''[:space:]]*\).*/\1@\2/p')
            [ -z "$uses_value" ] && continue
            action=$(echo "$uses_value" | cut -d@ -f1)
            ref=$(echo "$uses_value" | cut -d@ -f2)

            local action_lower
            action_lower=$(echo "$action" | tr '[:upper:]' '[:lower:]')

            # Check aquasecurity/setup-trivy
            if [ "$action_lower" = "aquasecurity/setup-trivy" ]; then
                case "$ref" in
                    0.2.0|0.2.1|0.2.2|0.2.3|0.2.4|0.2.5|0.2.6)
                        log_critical "${wf}:${line_num} - uses: ${action}@${ref}" "All setup-trivy 0.2.x tags were hijacked" "Pin to a verified SHA or remove"
                        add_json_finding "ghactions" "critical" "Hijacked setup-trivy@${ref}" "${wf}:${line_num}" "Pin to verified SHA"
                        ((findings++))
                        ;;
                esac
            fi

            # Check aquasecurity/trivy-action
            if [ "$action_lower" = "aquasecurity/trivy-action" ]; then
                # Safe: v-prefixed semver tags
                if echo "$ref" | command grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+'; then
                    : # safe
                # Safe: 0.35.0
                elif [ "$ref" = "0.35.0" ]; then
                    : # safe
                # Check against known malicious commit SHAs
                elif echo "$ref" | command grep -qE '^[0-9a-f]{6,40}$'; then
                    local sha_malicious=0
                    for known_sha in "${MALICIOUS_ACTION_SHAS[@]}"; do
                        if echo "$ref" | command grep -q "^${known_sha}"; then
                            log_critical "${wf}:${line_num} - uses: ${action}@${ref}" "SHA matches known malicious commit" "Update to safe ref"
                            add_json_finding "ghactions" "critical" "Malicious SHA-pinned trivy-action" "${wf}:${line_num}" "Update ref"
                            ((findings++))
                            sha_malicious=1
                            break
                        fi
                    done
                    [ "$sha_malicious" -eq 0 ] && {
                        log_info "${wf}:${line_num} - uses: ${action}@${ref}" "SHA-pinned ref - verify commit is not from compromised window (Mar 19-24, 2026)"
                    }
                else
                    # All other refs (branch names, non-v tags) are suspicious
                    log_high "${wf}:${line_num} - uses: ${action}@${ref}" "Non-semver, non-SHA ref - verify not from compromised window (Mar 19-24, 2026)" "Pin to v-prefixed semver tag or verified SHA"
                    add_json_finding "ghactions" "high" "Suspicious trivy-action ref" "${wf}:${line_num} ref=${ref}" "Pin to safe ref"
                    ((findings++))
                fi
            fi

            # Check Checkmarx/kics-github-action (v1.x all hijacked, v2.0.0-v2.1.20 hijacked)
            if [ "$action_lower" = "checkmarx/kics-github-action" ]; then
                if echo "$ref" | command grep -qE '^v1(\.|$)'; then
                    log_critical "${wf}:${line_num} - uses: ${action}@${ref}" "KICS action v1.x tags were all hijacked" "Pin to verified SHA after v2.1.20 or remove"
                    add_json_finding "ghactions" "critical" "Hijacked KICS action@${ref}" "${wf}:${line_num}" "Update to post-compromise version"
                    ((findings++))
                elif echo "$ref" | command grep -qE '^v2\.(0\.|1\.(([0-9]|1[0-9]|20)(\.|$)))'; then
                    log_critical "${wf}:${line_num} - uses: ${action}@${ref}" "KICS action v2.0.0-v2.1.20 were hijacked" "Pin to verified SHA after v2.1.20 or remove"
                    add_json_finding "ghactions" "critical" "Hijacked KICS action@${ref}" "${wf}:${line_num}" "Update to post-compromise version"
                    ((findings++))
                fi
            fi

            # Check Checkmarx/ast-github-action
            if [ "$action_lower" = "checkmarx/ast-github-action" ]; then
                if [ "$ref" = "v2.3.28" ]; then
                    log_critical "${wf}:${line_num} - uses: ${action}@${ref}" "Known compromised version" "Update to v2.3.29+"
                    add_json_finding "ghactions" "critical" "Compromised ast-github-action" "${wf}:${line_num}" "Update version"
                    ((findings++))
                fi
            fi

        done < <(command grep -n "uses:" "$wf" 2>/dev/null)

        # Check for injected step names
        if command grep -qi "Github security scan\|Setup environment" "$wf" 2>/dev/null; then
            local matches
            matches=$(command grep -ni "Github security scan\|Setup environment" "$wf" 2>/dev/null)
            log_high "Suspicious step name in: $wf" "$matches" "Inspect workflow for injected steps"
            add_json_finding "ghactions" "high" "Suspicious step name" "$wf: $matches" "Inspect for injection"
            ((findings++))
        fi

        # Check for appleboy/scp-action@master (used in trivy injection)
        if command grep -qi "appleboy/scp-action@master" "$wf" 2>/dev/null; then
            log_medium "appleboy/scp-action@master found: $wf" "Used in TeamPCP trivy injection chain"
            add_json_finding "ghactions" "medium" "appleboy/scp-action@master in $wf" "Used in TeamPCP injection chain" "Pin to specific version"
            ((findings++))
        fi

        # Check for tpcp-docs / docs-tpcp references
        if command grep -qiE "tpcp-docs|docs-tpcp" "$wf" 2>/dev/null; then
            log_critical "TeamPCP fallback exfil repo reference in: $wf" "Contains 'tpcp-docs' or 'docs-tpcp'" "Remove immediately"
            add_json_finding "ghactions" "critical" "TeamPCP exfil reference" "$wf" "Remove"
            ((findings++))
        fi
    done

    [ "$findings" -eq 0 ] && log_clean "No malicious GitHub Actions references found (checked $workflow_count files)"

    local duration=$(( $(date +%s) - start_time ))
    add_json_scanner_result "ghactions" "$([ "$findings" -gt 0 ] && echo found || echo clean)" "$duration" "$findings"
}

# =============================================================================
# SCANNER 6: NETWORK
# =============================================================================
scan_network() {
    print_section "Network connections & DNS..."
    local start_time findings=0
    start_time=$(date +%s)

    # DNS resolution check
    if [ "$NO_DNS" -eq 0 ]; then
        log_verbose "Checking DNS resolution for C2 domains..."
        for domain in "${C2_DOMAINS[@]}"; do
            local resolved=""
            if cmd_exists dig; then
                resolved=$(dig +short "$domain" 2>/dev/null | head -1)
            elif cmd_exists nslookup; then
                resolved=$(nslookup "$domain" 2>/dev/null | command grep -A1 "Name:" | command grep "Address:" | awk '{print $2}' | head -1)
            elif cmd_exists host; then
                resolved=$(host "$domain" 2>/dev/null | command grep "has address" | awk '{print $NF}' | head -1)
            fi

            if [ -n "$resolved" ] && [ "$resolved" != ";;" ]; then
                log_info "C2 domain resolves: $domain -> $resolved" "Domain is active - check if any local process contacted it"
                add_json_finding "network" "info" "C2 domain active: $domain" "Resolves to $resolved" "Monitor for connections"
                ((findings++))
            fi
        done
    else
        log_skip "DNS checks disabled (--no-dns)"
    fi

    # Active connection check
    log_verbose "Checking active network connections..."
    local conn_output=""
    if cmd_exists ss; then
        conn_output=$(ss -tunp 2>/dev/null)
    elif cmd_exists netstat; then
        conn_output=$(netstat -tunp 2>/dev/null)
    elif cmd_exists lsof; then
        conn_output=$(lsof -i -n -P 2>/dev/null)
    fi

    if [ -n "$conn_output" ]; then
        # Check known C2 IPs
        for ip in "${C2_IPS[@]}"; do
            local matches
            matches=$(echo "$conn_output" | command grep "$ip")
            if [ -n "$matches" ]; then
                log_critical "Active connection to known C2 IP: $ip" "$matches" "Kill the process and investigate"
                add_json_finding "network" "critical" "Active C2 connection: $ip" "$matches" "Kill process and investigate"
                ((findings++))
            fi
        done

        # Check for Python-urllib user agent in process names (heuristic)
        local python_conns
        python_conns=$(echo "$conn_output" | command grep -i "python" 2>/dev/null)
        if [ -n "$python_conns" ] && [ "$VERBOSE" -eq 1 ]; then
            log_verbose "Python processes with network connections found (check manually):"
            echo "$python_conns" | head -5
        fi
    else
        log_skip "No network connection tool available (ss/netstat/lsof)"
    fi

    # Log file scanning
    if [ -n "$LOG_PATH" ]; then
        log_verbose "Scanning log files in $LOG_PATH..."
        local log_findings=0

        # Search for C2 domains in logs
        local c2_pattern
        c2_pattern=$(printf '%s\\|' "${C2_DOMAINS[@]}" | sed 's/\\|$//')
        while IFS= read -r logfile; do
            [ -z "$logfile" ] && continue
            local matches
            matches=$(command grep -l "$c2_pattern" "$logfile" 2>/dev/null)
            if [ -n "$matches" ]; then
                log_high "C2 domain found in log: $logfile" "$(command grep -c "$c2_pattern" "$logfile" 2>/dev/null) matches" "Investigate affected systems"
                add_json_finding "network" "high" "C2 in logs: $logfile" "Multiple C2 domain references" "Investigate"
                ((findings++))
                ((log_findings++))
            fi
        done < <(find "$LOG_PATH" -type f -name "*.log" 2>/dev/null | head -50)

        # Search for exfiltration header
        while IFS= read -r logfile; do
            [ -z "$logfile" ] && continue
            if command grep -q "tpcp.tar.gz\|X-Filename.*tpcp" "$logfile" 2>/dev/null; then
                log_critical "Exfiltration indicator in log: $logfile" "Contains 'tpcp.tar.gz' or X-Filename header" "Investigate data exfiltration"
                add_json_finding "network" "critical" "Exfil indicator: $logfile" "tpcp.tar.gz reference" "Investigate"
                ((findings++))
                ((log_findings++))
            fi
            if command grep -q "Python-urllib" "$logfile" 2>/dev/null; then
                log_medium "Python-urllib User-Agent in: $logfile" "May indicate automated credential theft"
                add_json_finding "network" "medium" "Python-urllib in $logfile" "May indicate automated theft" "Investigate"
                ((findings++))
                ((log_findings++))
            fi
        done < <(find "$LOG_PATH" -type f \( -name "*.log" -o -name "access*" -o -name "audit*" \) 2>/dev/null | head -50)

        [ "$log_findings" -eq 0 ] && log_clean "No IOC indicators in log files"
    fi

    [ "$findings" -eq 0 ] && log_clean "No network IOC indicators detected"

    local duration=$(( $(date +%s) - start_time ))
    add_json_scanner_result "network" "$([ "$findings" -gt 0 ] && echo found || echo clean)" "$duration" "$findings"
}

# =============================================================================
# SCANNER 7: KUBERNETES
# =============================================================================
scan_kubernetes() {
    print_section "Kubernetes cluster..."
    local start_time findings=0
    start_time=$(date +%s)

    if ! cmd_exists kubectl; then
        log_skip "kubectl not installed"
        add_json_scanner_result "kubernetes" "skipped" "0" "0" "kubectl not found"
        return
    fi

    # Check cluster connectivity
    if ! timeout 10 kubectl cluster-info >/dev/null 2>&1; then
        log_skip "No Kubernetes cluster reachable"
        add_json_scanner_result "kubernetes" "skipped" "0" "0" "No cluster reachable"
        return
    fi

    # Check for malicious pods (node-setup-* prefix)
    log_verbose "Checking pods for node-setup-* prefix..."
    local pods_json
    pods_json=$(timeout 30 kubectl get pods -A -o json 2>/dev/null)
    if [ -n "$pods_json" ]; then
        local malicious_pods
        malicious_pods=$(echo "$pods_json" | command grep -o '"name"[[:space:]]*:[[:space:]]*"node-setup-[^"]*"' 2>/dev/null)
        if [ -n "$malicious_pods" ]; then
            log_critical "Pods with 'node-setup-' prefix found" "$malicious_pods" "kubectl delete pod -n <ns> <pod>"
            add_json_finding "kubernetes" "critical" "Malicious node-setup pods" "$malicious_pods" "Delete pods"
            ((findings++))
        fi

        # Check for kamikaze/provisioner container names
        for cname in "kamikaze" "provisioner"; do
            local container_matches
            container_matches=$(echo "$pods_json" | command grep -B5 "\"name\"[[:space:]]*:[[:space:]]*\"${cname}\"" 2>/dev/null | command grep "\"name\"" | head -5)
            if [ -n "$container_matches" ]; then
                log_critical "Container named '${cname}' found in cluster" "$container_matches" "Inspect and remove affected pods/daemonsets"
                add_json_finding "kubernetes" "critical" "Malicious container: ${cname}" "$container_matches" "Delete resources"
                ((findings++))
            fi
        done
    else
        log_skip "Unable to list pods (RBAC permission denied?)"
    fi

    # Check for malicious DaemonSets
    log_verbose "Checking DaemonSets..."
    local ds_json
    ds_json=$(timeout 30 kubectl get daemonsets -A -o json 2>/dev/null)
    if [ -n "$ds_json" ]; then
        for ds_name in "host-provisioner-iran" "host-provisioner-std"; do
            if echo "$ds_json" | command grep -q "\"name\"[[:space:]]*:[[:space:]]*\"${ds_name}\""; then
                log_critical "Malicious DaemonSet found: ${ds_name}" "TeamPCP Kubernetes payload" "kubectl delete daemonset -n kube-system ${ds_name}"
                add_json_finding "kubernetes" "critical" "Malicious DaemonSet: ${ds_name}" "TeamPCP K8s payload" "kubectl delete daemonset -n kube-system ${ds_name}"
                ((findings++))
            fi
        done

        # Check for suspicious DaemonSets in kube-system using alpine:latest
        local suspicious_ds
        suspicious_ds=$(echo "$ds_json" | command grep -B2 -A20 '"namespace"[[:space:]]*:[[:space:]]*"kube-system"' 2>/dev/null \
            | command grep -B10 "alpine:latest" 2>/dev/null | command grep '"name"' | head -5)
        if [ -n "$suspicious_ds" ]; then
            log_medium "DaemonSet in kube-system using alpine:latest" "$suspicious_ds"
            add_json_finding "kubernetes" "medium" "Alpine DaemonSet in kube-system" "$suspicious_ds" "Inspect DaemonSet"
            ((findings++))
        fi

        # Check for tolerations with operator: Exists (deploys to ALL nodes)
        local toleration_ds
        toleration_ds=$(echo "$ds_json" | command grep -B30 '"operator"[[:space:]]*:[[:space:]]*"Exists"' 2>/dev/null \
            | command grep -A5 "kube-system" 2>/dev/null | command grep '"name"' | head -5)
        if [ -n "$toleration_ds" ]; then
            log_verbose "DaemonSets in kube-system with 'operator: Exists' tolerations found"
        fi
    else
        log_skip "Unable to list DaemonSets (RBAC permission denied?)"
    fi

    [ "$findings" -eq 0 ] && log_clean "No malicious Kubernetes resources found"

    local duration=$(( $(date +%s) - start_time ))
    add_json_scanner_result "kubernetes" "$([ "$findings" -gt 0 ] && echo found || echo clean)" "$duration" "$findings"
}

# =============================================================================
# SCANNER 8: OPENVSX / VS CODE EXTENSIONS
# =============================================================================
scan_openvsx() {
    print_section "VS Code / OpenVSX extensions..."
    local start_time findings=0
    start_time=$(date +%s)

    local ext_dirs=(
        "${HOME}/.vscode/extensions"
        "${HOME}/.vscode-server/extensions"
        "${HOME}/.vscode-insiders/extensions"
        "${HOME}/.config/VSCodium/extensions"
        "${HOME}/.local/share/code-server/extensions"
    )

    local checked=0
    for ext_dir in "${ext_dirs[@]}"; do
        [ -d "$ext_dir" ] || continue
        ((checked++))

        # Check for malicious extensions
        for ext_name in "ast-results" "cx-dev-assist"; do
            while IFS= read -r ext_path; do
                [ -z "$ext_path" ] && continue
                local pkg_json="${ext_path}/package.json"
                if [ -f "$pkg_json" ]; then
                    local version
                    version=$(command grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg_json" 2>/dev/null | sed 's/.*"version"[[:space:]]*:[[:space:]]*"//;s/"//')
                    if { [ "$ext_name" = "ast-results" ] && [ "$version" = "2.53.0" ]; } || \
                       { [ "$ext_name" = "cx-dev-assist" ] && [ "$version" = "1.7.0" ]; }; then
                        log_critical "Malicious extension: ${ext_name} v${version}" "In: $ext_path" "Remove: rm -rf '$ext_path'"
                        add_json_finding "openvsx" "critical" "Malicious extension: ${ext_name} v${version}" "$ext_path" "rm -rf $ext_path"
                        ((findings++))
                    fi
                fi
            done < <(find "$ext_dir" -maxdepth 1 -type d -name "*${ext_name}*" 2>/dev/null)
        done

        # Check for environmentAuthChecker.js (KICS malware)
        while IFS= read -r checker_file; do
            [ -z "$checker_file" ] && continue
            local hash
            hash=$(compute_sha256 "$checker_file")
            if [ "$hash" = "527f795a201a6bc114394c4cfd1c74dce97381989f51a4661aafbc93a4439e90" ]; then
                log_critical "KICS malware found: $checker_file" "SHA256 matches environmentAuthChecker.js" "Remove extension"
                add_json_finding "openvsx" "critical" "KICS malware" "SHA256 match at $checker_file" "Remove extension"
                ((findings++))
            fi
        done < <(find "$ext_dir" -name "environmentAuthChecker.js" 2>/dev/null)
    done

    # Also check via code CLI
    if cmd_exists code; then
        log_verbose "Checking via 'code --list-extensions'..."
        local ext_list
        ext_list=$(code --list-extensions --show-versions 2>/dev/null)
        if echo "$ext_list" | command grep -qi "ast-results@2.53.0\|cx-dev-assist@1.7.0"; then
            local ext_match
            ext_match=$(echo "$ext_list" | command grep -i 'ast-results\|cx-dev-assist')
            log_critical "Malicious extension installed (via code CLI)" "$ext_match" "code --uninstall-extension <id>"
            add_json_finding "openvsx" "critical" "Malicious extension via code CLI" "$ext_match" "code --uninstall-extension"
            ((findings++))
        fi
    fi

    if [ "$checked" -eq 0 ] && ! cmd_exists code; then
        log_skip "No VS Code extension directories found"
        add_json_scanner_result "openvsx" "skipped" "0" "0" "No VS Code found"
    elif [ "$findings" -eq 0 ]; then
        log_clean "No malicious VS Code extensions found"
        add_json_scanner_result "openvsx" "clean" "$(( $(date +%s) - start_time ))" "0"
    else
        add_json_scanner_result "openvsx" "found" "$(( $(date +%s) - start_time ))" "$findings"
    fi
}

# =============================================================================
# REPORT FUNCTIONS
# =============================================================================

print_banner() {
    [ "$QUIET" -eq 1 ] && return
    printf "\n${BOLD}"
    printf '%.0s=' {1..66}
    printf "\n  TeamPCP Supply Chain IOC Scanner v%s\n" "$VERSION"
    printf "  Campaign: March 19-24, 2026\n"
    printf "  Scan started: %s\n" "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    printf "  Scan path: %s\n" "$SCAN_PATH"
    printf '%.0s=' {1..66}
    printf "${RESET}\n"
}

print_summary() {
    local total=$((TOTAL_CRITICAL + TOTAL_HIGH + TOTAL_MEDIUM + TOTAL_INFO))
    local duration=$(( $(date +%s) - SCAN_START ))
    local status="CLEAN"
    local status_color="${GREEN}"
    if [ "$TOTAL_CRITICAL" -gt 0 ]; then
        status="COMPROMISED - Immediate action required"
        status_color="${RED_BG}"
    elif [ "$TOTAL_HIGH" -gt 0 ]; then
        status="SUSPICIOUS - Investigation needed"
        status_color="${YELLOW}"
    elif [ "$TOTAL_MEDIUM" -gt 0 ] || [ "$TOTAL_INFO" -gt 0 ]; then
        status="ATTENTION - Review recommended"
        status_color="${CYAN}"
    fi

    printf "\n${BOLD}"
    printf '%.0s=' {1..66}
    printf "\n  SCAN COMPLETE | Duration: %ss\n" "$duration"
    printf "  Findings: %s critical, %s high, %s medium, %s info\n" \
        "$TOTAL_CRITICAL" "$TOTAL_HIGH" "$TOTAL_MEDIUM" "$TOTAL_INFO"
    printf "  Status: ${status_color}%s${RESET}${BOLD}\n" "$status"
    printf '%.0s=' {1..66}
    printf "${RESET}\n\n"
}

write_json_report() {
    [ -z "$JSON_OUTPUT" ] && return

    local total=$((TOTAL_CRITICAL + TOTAL_HIGH + TOTAL_MEDIUM + TOTAL_INFO))
    local duration=$(( $(date +%s) - SCAN_START ))
    local status="clean"
    [ "$TOTAL_CRITICAL" -gt 0 ] && status="compromised"
    [ "$TOTAL_CRITICAL" -eq 0 ] && [ "$TOTAL_HIGH" -gt 0 ] && status="suspicious"

    local escaped_scan_path escaped_hostname escaped_scanners
    escaped_scan_path=$(json_escape "$SCAN_PATH")
    escaped_hostname=$(json_escape "$(hostname)")
    escaped_scanners=$(json_escape "$SCANNERS_TO_RUN")

    cat > "$JSON_OUTPUT" << JSONEOF
{
  "scan_metadata": {
    "tool": "teampcp-ioc-scan",
    "version": "${VERSION}",
    "campaign": "TeamPCP March 2026",
    "scan_timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
    "scan_duration_sec": ${duration},
    "hostname": "${escaped_hostname}",
    "platform": "$(uname -s)",
    "scan_path": "${escaped_scan_path}",
    "scanners_run": "${escaped_scanners}"
  },
  "summary": {
    "status": "${status}",
    "total_findings": ${total},
    "by_severity": {
      "critical": ${TOTAL_CRITICAL},
      "high": ${TOTAL_HIGH},
      "medium": ${TOTAL_MEDIUM},
      "info": ${TOTAL_INFO}
    }
  },
  "findings": [${JSON_FINDINGS}],
  "scanner_results": [${JSON_SCANNER_RESULTS}]
}
JSONEOF

    printf "${GREEN}JSON report written to: %s${RESET}\n" "$JSON_OUTPUT"
}

# =============================================================================
# ARGUMENT PARSING
# =============================================================================
show_help() {
    cat << 'HELPEOF'
TeamPCP Supply Chain IOC Scanner v1.0
Campaign: March 19-24, 2026

Detects indicators of compromise from the TeamPCP multi-ecosystem supply chain
attack across PyPI, npm, GitHub Actions, Docker, OpenVSX, and Kubernetes.

Usage: ./teampcp_scan.sh [OPTIONS]

Options:
  -p, --scan-path PATH    Root path to scan (default: $HOME)
  -o, --json-output FILE  Write JSON report to FILE
  -s, --scanners LIST     Scanners to run, comma-separated (default: all)
                          Options: filesystem,pypi,npm,docker,ghactions,
                                   network,kubernetes,openvsx
      --no-color          Disable colored output
      --no-dns            Skip DNS resolution checks
      --log-path PATH     Path to log files for network IOC search
  -v, --verbose           Show detailed output
  -q, --quiet             Only show findings
  -h, --help              Show this help

Examples:
  ./teampcp_scan.sh                              # Full scan
  ./teampcp_scan.sh -o report.json               # With JSON report
  ./teampcp_scan.sh -s filesystem,pypi           # Specific scanners
  ./teampcp_scan.sh -p /path/to/project          # Scan specific path
  ./teampcp_scan.sh --no-dns -q                  # Quiet, no DNS queries

Reference:
  https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
HELPEOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -p|--scan-path)   [ $# -lt 2 ] && { printf "Error: %s requires an argument\n" "$1" >&2; exit 1; }; SCAN_PATH="$2"; shift 2 ;;
            -o|--json-output) [ $# -lt 2 ] && { printf "Error: %s requires an argument\n" "$1" >&2; exit 1; }; JSON_OUTPUT="$2"; shift 2 ;;
            -s|--scanners)    [ $# -lt 2 ] && { printf "Error: %s requires an argument\n" "$1" >&2; exit 1; }; SCANNERS_TO_RUN="$2"; shift 2 ;;
            --no-color)       NO_COLOR=1; RED='' RED_BG='' YELLOW='' GREEN='' CYAN='' DIM='' BOLD='' RESET=''; shift ;;
            --no-dns)         NO_DNS=1; shift ;;
            --log-path)       [ $# -lt 2 ] && { printf "Error: %s requires an argument\n" "$1" >&2; exit 1; }; LOG_PATH="$2"; shift 2 ;;
            -v|--verbose)     VERBOSE=1; shift ;;
            -q|--quiet)       QUIET=1; shift ;;
            -h|--help)        show_help; exit 0 ;;
            *)                printf "Unknown option: %s\nTry: ./teampcp_scan.sh --help\n" "$1"; exit 1 ;;
        esac
    done
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    parse_args "$@"
    SCAN_START=$(date +%s)

    # Validate scan path
    if [ ! -d "$SCAN_PATH" ]; then
        printf "${RED}Error: Scan path does not exist: %s${RESET}\n" "$SCAN_PATH"
        exit 1
    fi

    # Validate JSON output path is writable
    if [ -n "$JSON_OUTPUT" ]; then
        local json_dir
        json_dir=$(dirname "$JSON_OUTPUT")
        if [ ! -w "$json_dir" ]; then
            printf "${RED}Error: Cannot write to: %s${RESET}\n" "$json_dir"
            exit 1
        fi
    fi

    # Validate scanner names
    if [ "$SCANNERS_TO_RUN" != "all" ]; then
        local valid_scanners="filesystem,pypi,npm,docker,ghactions,network,kubernetes,openvsx"
        IFS=',' read -ra requested <<< "$SCANNERS_TO_RUN"
        for s in "${requested[@]}"; do
            if ! echo ",$valid_scanners," | command grep -q ",$s,"; then
                printf "${YELLOW}Warning: Unknown scanner '%s' (valid: %s)${RESET}\n" "$s" "$valid_scanners" >&2
            fi
        done
    fi

    # Detect environment
    if [ -f "/.dockerenv" ] || command grep -q "docker\|containerd\|lxc" /proc/1/cgroup 2>/dev/null; then
        [ "$QUIET" -eq 0 ] && printf "${YELLOW}Note: Running inside a container. Some host-level checks may be limited.${RESET}\n"
    fi

    print_banner

    # Run scanners
    should_run_scanner "filesystem" && scan_filesystem
    should_run_scanner "pypi"       && scan_pypi
    should_run_scanner "npm"        && scan_npm
    should_run_scanner "docker"     && scan_docker
    should_run_scanner "ghactions"  && scan_github_actions
    should_run_scanner "network"    && scan_network
    should_run_scanner "kubernetes" && scan_kubernetes
    should_run_scanner "openvsx"    && scan_openvsx

    print_summary
    write_json_report

    # Exit code: 0 = clean, 1 = findings, 2 = error
    [ "$TOTAL_CRITICAL" -gt 0 ] && exit 1
    [ "$TOTAL_HIGH" -gt 0 ] && exit 1
    exit 0
}

main "$@"
