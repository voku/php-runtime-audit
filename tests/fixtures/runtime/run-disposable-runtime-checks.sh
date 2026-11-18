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
mkdir "$production"
cp -a -- "$project_root/src" "$project_root/bin" "$project_root/resources" \
    "$project_root/composer.json" "$project_root/composer.lock" "$project_root/vendor" "$production/"
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
    # The collector verifies each worker's mount namespace and process root before
    # attributing configuration. Linux hides those links from sibling processes
    # without CAP_SYS_PTRACE, even when they run under the same container UID.
    # Keep this capability inside the disposable, network-disabled audit container.
    container=$(docker_local run --detach --network none --cap-add SYS_PTRACE --security-opt no-new-privileges \
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
