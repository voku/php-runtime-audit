#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
fixture_parent=${TMPDIR:-$project_root}
fixture_dir=$(mktemp -d "$fixture_parent/.runtime-fixture.XXXXXX")
containers=()

docker_local() {
    env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
        docker --host=unix:///var/run/docker.sock "$@"
}

cleanup() {
    status=$?
    trap - EXIT
    for container in "${containers[@]}"; do
        if ! docker_local rm --force "$container" >/dev/null; then
            status=1
        fi
    done
    rm -rf -- "$fixture_dir"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

command -v php >/dev/null
command -v composer >/dev/null
docker_local info >/dev/null
test -d "$project_root/vendor"

production="$fixture_dir/project"
mkdir "$production" "$production/tools"
cp -a -- "$project_root/src" "$project_root/bin" "$project_root/resources" "$project_root/LICENSE" \
    "$project_root/composer.json" "$project_root/composer.lock" "$project_root/vendor" "$production/"
cp -- "$project_root/tools/build-phar.php" "$production/tools/"
# Reuse the locked installed files; remove development packages without network,
# plugins or repository scripts. The audited runtime loads production code only.
if ! COMPOSER_DISABLE_NETWORK=1 composer install --working-dir="$production" --no-dev \
    --no-plugins --no-scripts --no-interaction --no-progress >"$fixture_dir/composer.log" 2>&1; then
    cat "$fixture_dir/composer.log" >&2
    exit 1
fi

cat >"$fixture_dir/pool.conf" <<'CONF'
[www]
php_admin_value[session.upload_progress.enabled] = 1
php_admin_value[session.serialize_handler] = php_serialize
CONF

run_fixture() {
    kind=$1
    image=$2
    process_name=$3
    label=$4
    expected_version_prefix=$5
    docker_local image inspect "$image" >/dev/null 2>&1 || docker_local pull "$image" >/dev/null
    mounts=(-v "$production:/audit:ro")
    if [ "$kind" = fpm ]; then
        mounts+=(-v "$fixture_dir/pool.conf:/usr/local/etc/php-fpm.d/zz-pra-fixture.conf:ro")
    fi
    container=$(docker_local run --detach --network none --security-opt no-new-privileges \
        "${mounts[@]}" "$image")
    containers+=("$container")
    ready=false
    for attempt in {1..30}; do
        if docker_local exec "$container" php -r \
            'exit(trim((string) file_get_contents("/proc/1/comm")) === $argv[1] ? 0 : 1);' \
            "$process_name" >/dev/null 2>&1; then
            ready=true
            break
        fi
        sleep 0.2
    done
    if [ "$ready" != true ]; then
        docker_local logs "$container" >&2
        exit 1
    fi
    # bin/php-runtime-audit-inventory deliberately refuses to run when register_argc_argv is
    # disabled (tests/RuntimeInventory/InventoryCliArgumentsTest.php covers this; it is a security
    # guard, not a bug, so it must not be weakened). The php:8.5-fpm image's active configuration
    # leaves that ini directive off, unlike the 8.2/8.4 images used elsewhere in this script, so
    # invoke it explicitly here -- exactly what an administrator would need to do to run this CLI
    # tool against a host whose default differs.
    docker_local exec --workdir /audit "$container" php -d register_argc_argv=1 bin/php-runtime-audit-inventory \
        >"$fixture_dir/$label.json"
    php "$project_root/tests/fixtures/runtime/assert-disposable-report.php" \
        "$fixture_dir/$label.json" "$kind" "$expected_version_prefix"
}

# Immutable multi-platform upstream image references; no host ports are exposed.
# audit-tool-runtime-version is whatever PHP this script itself runs under (the CI job's
# matrix version); audited-runtime-version is the pinned image version below, verified against
# the inventory's own worker/CLI facts by assert-disposable-report.php's expected-prefix check.
# This covers FPM and Apache real workers on both the previously-verified 8.2/8.4 pair and on
# PHP 8.5, so a passing run cannot be mistaken for a fixture-only or same-version-coincidence result.
# FPM's full dotted version (e.g. "8.2.35") comes from invoking its own binary directly, so it is
# checked against worker.N.version. A live Apache process can't be probed that way, and current
# official PHP images load an unversioned libphp.so with no version in the module path at all, so
# apache coverage here is proven via the isolated CLI probe's own dotted version instead (each
# image has exactly one PHP installed) -- see assert-disposable-report.php for both checks.
run_fixture fpm 'php:8.2-fpm@sha256:77900c43ba8b8f2f61c73bcf68afbfb1b72a349052472e7640d402ef998754b3' php-fpm fpm-8.2 '8.2.'
run_fixture apache 'php:8.4-apache@sha256:c6527b06c772a2c3cae648ce58c23a2a12ed2fed41cdfb0619ea64be008cc601' apache2 apache-8.4 '8.4.'
run_fixture fpm 'php:8.5-fpm@sha256:f49965c6e6a237eb3b27a6fc565e167839dc8abc65ee0652af0078f6ecdf4bbd' php-fpm fpm-8.5 '8.5.'
run_fixture apache 'php:8.5-apache@sha256:7cd25eb48f9763dfeabe8fda3939897aca2001802fadeafa1b602f26c735ef96' apache2 apache-8.5 '8.5.'

# Session-store scenarios (issue #38 slice 4): configuration-only inputs from
# tests/fixtures/runtime/session-scenarios, mounted read-only into the same pinned, network-less
# images. Only the two-pool scenarios send requests, to validate against ground truth below.
session_fpm_image='php:8.2-fpm@sha256:77900c43ba8b8f2f61c73bcf68afbfb1b72a349052472e7640d402ef998754b3'
session_apache_image='php:8.4-apache@sha256:c6527b06c772a2c3cae648ce58c23a2a12ed2fed41cdfb0619ea64be008cc601'
scenario_root="$project_root/tests/fixtures/runtime/session-scenarios"
session_assert="$project_root/tests/fixtures/runtime/assert-disposable-session-report.php"
ground_truth_assert="$project_root/tests/fixtures/runtime/assert-session-ground-truth.php"
session_probe="$project_root/tests/fixtures/runtime/session-probe"
ground_truth_validated=()

# The same production copy, packaged as the PHAR users download, so one scenario also proves the
# PHAR reaches the same verdicts as the source tree.
php -d phar.readonly=0 "$production/tools/build-phar.php" "$fixture_dir/php-runtime-audit.phar" >/dev/null

run_session_fixture() {
    kind=$1
    image=$2
    process_name=$3
    scenario=$4
    mode=${5:-source}
    scenario_dir="$scenario_root/$scenario"
    test -d "$scenario_dir"
    mounts=(-v "$production:/audit:ro" -v "$fixture_dir/php-runtime-audit.phar:/opt/php-runtime-audit.phar:ro"
        -v "$session_probe:/opt/pra-probe:ro")
    if [ -f "$scenario_dir/pools.conf" ]; then
        mounts+=(-v "$scenario_dir/pools.conf:/usr/local/etc/php-fpm.d/zz-pra-session.conf:ro")
    fi
    if [ -f "$scenario_dir/session.ini" ]; then
        mounts+=(-v "$scenario_dir/session.ini:/usr/local/etc/php/conf.d/zz-pra-session.ini:ro")
    fi
    container=$(docker_local run --detach --network none --security-opt no-new-privileges \
        "${mounts[@]}" "$image")
    containers+=("$container")
    pools=()
    if [ -f "$scenario_dir/pools.conf" ]; then
        mapfile -t pools < <(sed -n 's/^\[\([A-Za-z0-9_-]*\)\]$/\1/p' "$scenario_dir/pools.conf")
    fi
    ready=false
    for attempt in {1..50}; do
        # Ready once the expected master runs and every scenario pool has spawned a worker.
        if docker_local exec "$container" php -r '
            if (trim((string) file_get_contents("/proc/1/comm")) !== $argv[1]) { exit(1); }
            $titles = "";
            foreach (glob("/proc/[0-9]*/cmdline") ?: [] as $file) { $titles .= (string) @file_get_contents($file) . "\n"; }
            foreach (array_slice($argv, 2) as $pool) { if (!str_contains($titles, "pool " . $pool)) { exit(1); } }
            exit(0);' "$process_name" "${pools[@]}" >/dev/null 2>&1; then
            ready=true
            break
        fi
        sleep 0.2
    done
    if [ "$ready" != true ]; then
        docker_local logs "$container" >&2
        exit 1
    fi
    label="session-$scenario-$mode"
    if [ "$mode" = phar ]; then
        docker_local exec "$container" php -d register_argc_argv=1 /opt/php-runtime-audit.phar inventory \
            >"$fixture_dir/$label.json"
    else
        docker_local exec --workdir /audit "$container" php -d register_argc_argv=1 bin/php-runtime-audit-inventory \
            >"$fixture_dir/$label.json"
    fi
    plan_args=()
    if [ "$mode" = remediation ]; then
        # inventory -> report -> remediation, on the host, with the production copy.
        php "$production/bin/php-runtime-audit-report" --report "$fixture_dir/$label.md" \
            <"$fixture_dir/$label.json" >"$fixture_dir/$label.plan.json"
        test -s "$fixture_dir/$label.md"
        plan_args=("$fixture_dir/$label.plan.json")
    fi
    php "$session_assert" "$fixture_dir/$label.json" "$scenario" "${plan_args[@]}"
    if [ "${#pools[@]}" -eq 2 ]; then
        if [ "${pools[0]}" != writer ] || [ "${pools[1]}" != reader ]; then
            echo "Two-pool scenario $scenario must name its pools [writer] then [reader] for ground-truth validation." >&2
            exit 1
        fi
        validate_session_ground_truth "$container" "$scenario_dir/pools.conf" "$label"
        ground_truth_validated+=("$scenario")
    fi
}

# Validation against ground truth, not only self-consistency: after the read-only inventory,
# send benign FastCGI requests over the container's own loopback (it still has no network) and
# observe whether the writer pool's session really lands in the reader pool's store and whether
# the reader can decode it. The probe stores one plain string, never objects.
validate_session_ground_truth() {
    container=$1
    pools_file=$2
    label=$3
    probe=(docker_local exec "$container" php /opt/pra-probe/fastcgi-request.php)
    script=/opt/pra-probe/www/session.php
    pool_port() {
        awk -v pool="[$1]" '$0 == pool { in_pool = 1; next } /^\[/ { in_pool = 0 }
            in_pool && $1 == "listen" { sub(/.*:/, "", $3); print $3; exit }' "$pools_file"
    }
    writer_port=$(pool_port writer)
    reader_port=$(pool_port reader)
    # The pools' session directories do not exist in the image; create them for the probe only.
    while read -r directory; do
        docker_local exec "$container" mkdir -p "$directory"
        docker_local exec "$container" chown www-data:www-data "$directory"
    done < <(sed -n 's/^php_admin_value\[session\.save_path\] = \(\/[A-Za-z0-9._\/-]*\)$/\1/p' "$pools_file" | sort -u)
    session_id="pragroundtruth$RANDOM"
    reader_info=$("${probe[@]}" "$reader_port" "$script" "op=info")
    writer_result=$("${probe[@]}" "$writer_port" "$script" "op=write&id=$session_id")
    live_dir='$path = (string) json_decode($argv[1], true, 8, JSON_THROW_ON_ERROR)["save_path"];
        // The files handler accepts "N;" / "N;MODE;" prefixes; the directory is the last segment.
        $directory = substr((string) strrchr(";" . $path, ";"), 1);
        if ($directory === "" || $directory[0] !== "/" || preg_match("/\\A[1-9][0-9]*;/", $path) === 1) {
            // A depth N > 0 spreads sessions over subdirectories; this probe only checks flat stores.
            fwrite(STDERR, "Probe needs an explicit absolute, flat save_path.\n");
            exit(1);
        }
        echo rtrim($directory, "/");'
    reader_path=$(php -r "$live_dir" "$reader_info")
    writer_path=$(php -r "$live_dir" "$writer_result")
    # The writer really persisted its session (not just set it in memory).
    persisted=false
    if docker_local exec "$container" test -s "$writer_path/sess_$session_id"; then
        persisted=true
    fi
    # Shared store: the writer's session file exists in the reader's live save_path before the
    # reader starts a session there (starting one would create an empty file itself).
    shared=false
    if docker_local exec "$container" test -s "$reader_path/sess_$session_id"; then
        shared=true
    fi
    reader_result=$("${probe[@]}" "$reader_port" "$script" "op=read&id=$session_id")
    php -r '
        $writer = json_decode($argv[1], true, 8, JSON_THROW_ON_ERROR);
        $reader = json_decode($argv[2], true, 8, JSON_THROW_ON_ERROR);
        echo json_encode([
            "writer_read_back" => ($writer["read_back"] ?? null) === true && $argv[4] === "true",
            "shared_store" => $argv[3] === "true",
            "reader_started" => ($reader["started"] ?? null) === true,
            "reader_decodes" => ($reader["started"] ?? null) === true && ($reader["read_back"] ?? null) === true,
            "reader_start_error" => is_string($reader["start_error"] ?? null) ? $reader["start_error"] : null,
            "writer_serializer" => $writer["serializer"] ?? null,
            "reader_serializer" => $reader["serializer"] ?? null,
        ], JSON_THROW_ON_ERROR);' "$writer_result" "$reader_result" "$shared" "$persisted" >"$fixture_dir/$label.ground-truth.json"
    php "$ground_truth_assert" "$fixture_dir/$label.json" "$fixture_dir/$label.ground-truth.json"
}

run_session_fixture fpm "$session_fpm_image" php-fpm fpm-shared-store-mismatch remediation
run_session_fixture fpm "$session_fpm_image" php-fpm fpm-shared-store-mismatch phar
run_session_fixture fpm "$session_fpm_image" php-fpm fpm-isolated-stores
run_session_fixture fpm "$session_fpm_image" php-fpm fpm-shared-store-same-serializer
run_session_fixture fpm "$session_fpm_image" php-fpm fpm-no-session-config
run_session_fixture fpm "$session_fpm_image" php-fpm fpm-upload-progress-disabled
run_session_fixture fpm "$session_fpm_image" php-fpm fpm-files-backend
run_session_fixture fpm "$session_fpm_image" php-fpm fpm-redis-dsn
run_session_fixture apache "$session_apache_image" apache2 apache-files-backend-redacted-dsn

# Every two-pool scenario must really have been validated against ground truth; a renamed,
# skipped or removed scenario must not turn the validation into a silent no-op.
for expected in fpm-shared-store-mismatch fpm-isolated-stores fpm-shared-store-same-serializer; do
    validated=false
    for scenario in "${ground_truth_validated[@]}"; do
        if [ "$scenario" = "$expected" ]; then
            validated=true
        fi
    done
    if [ "$validated" != true ]; then
        echo "Ground-truth validation did not run for $expected." >&2
        exit 1
    fi
done
echo "ground truth validated for ${#ground_truth_validated[@]} two-pool runs."
