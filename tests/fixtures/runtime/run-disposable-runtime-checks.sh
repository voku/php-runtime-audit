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
    docker_local exec --workdir /audit "$container" php bin/php-runtime-audit-inventory \
        >"$fixture_dir/$kind.json"
    php "$project_root/tests/fixtures/runtime/assert-disposable-report.php" "$fixture_dir/$kind.json" "$kind"
}

# Immutable multi-platform upstream image references; no host ports are exposed.
run_fixture fpm 'php:8.2-fpm@sha256:77900c43ba8b8f2f61c73bcf68afbfb1b72a349052472e7640d402ef998754b3' php-fpm
run_fixture apache 'php:8.4-apache@sha256:c6527b06c772a2c3cae648ce58c23a2a12ed2fed41cdfb0619ea64be008cc601' apache2
