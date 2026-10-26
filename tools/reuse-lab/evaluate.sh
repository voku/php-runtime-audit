#!/usr/bin/env bash
# Read-only, pinned upstream evaluation on an ephemeral GitHub runner.
# Do not execute upstream code on the host runner.
set -Eeuo pipefail
candidate="${1:-}"
case "$candidate" in
  cloudflare|php2shell-doctor|p2selfcheck|bashclub) ;;
  *) echo "Unapproved reuse candidate" >&2; exit 2 ;;
esac

root="${GITHUB_WORKSPACE:-$(pwd)}"
manifest="$root/tools/reuse-lab/candidates.json"
result="$root/reuse-lab-results/$candidate"
mkdir -p "$result"
values="$(python3 - "$manifest" "$candidate" <<'PY'
import json, sys
e = json.load(open(sys.argv[1], encoding='utf-8'))['candidates'][sys.argv[2]]
for k in ('repository','sha','license','image','check'):
    print(e[k])
PY
)"
mapfile -t config <<<"$values"
repository="${config[0]}"
sha="${config[1]}"
license="${config[2]}"
container_image="${config[3]}"
check="${config[4]}"

src="${RUNNER_TEMP:-/tmp}/php-runtime-audit-upstream-$candidate"
git init -q "$src"
git -C "$src" remote add origin "https://github.com/$repository.git"
GIT_TERMINAL_PROMPT=0 timeout 120s git -C "$src" fetch --quiet --no-tags --depth=1 origin "$sha"
git -C "$src" -c advice.detachedHead=false checkout --quiet --detach FETCH_HEAD
observed="$(git -C "$src" rev-parse HEAD)"
test "$observed" = "$sha"
test -f "$src/LICENSE"
find "$src" -maxdepth 2 -type f -not -path '*/.git/*' -print0 | sort -z | xargs -0 -r sha256sum > "$result/source-file-hashes.txt"
echo "$observed" > "$result/upstream-commit.txt"

# Fetch images before entering the offline sandbox; record the actual local image ID.
timeout 180s docker pull "$container_image" >/dev/null
image_id="$(docker image inspect "$container_image" --format '{{.Id}}')"
case "$candidate" in
  cloudflare) command=(node --test skills/security-audit/validate-findings.test.cjs skills/security-audit/validate-coverage-ledger.test.cjs) ;;
  php2shell-doctor) command=(go test -count=1 ./...) ;;
  p2selfcheck) command=(sh -c 'php -l p2selfcheck.php && php p2selfcheck.php') ;;
  bashclub) command=(bash -n php2shell-forensic-check) ;;
esac

set +e
timeout 300s docker run --rm \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --user 65534:65534 --pids-limit 128 --memory 1024m --cpus 2 \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=384m \
  -e HOME=/tmp -e GOCACHE=/tmp/go-cache -e GOPATH=/tmp/go \
  -e GOTOOLCHAIN=local -e GOPROXY=off -e GOSUMDB=off \
  -v "$src:/src:ro" -w /src "$container_image" "${command[@]}" \
  >"$result/output.log" 2>&1
exit_code=$?
set -e
# Limit logs copied to CI stdout; retain the full isolated test output in artifact.
tail -n 65 "$result/output.log"
python3 - "$result/result.json" "$candidate" "$repository" "$sha" "$license" "$container_image" "$image_id" "$check" "$exit_code" <<'PY'
import json, sys, datetime
out, candidate, repo, sha, lic, image, digest, command, status = sys.argv[1:]
record = {
  'schema_version': 1, 'status': 'pass' if status == '0' else 'fail',
  'exit_code': int(status), 'candidate': candidate, 'repository': repo,
  'source_commit': sha, 'declared_license': lic,
  'sandbox_image': image, 'sandbox_image_id': digest,
  'check': command, 'source_execution_network': 'disabled',
  'source_mount': 'read_only', 'executor': 'ephemeral_github_actions_docker',
  'tested_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
  'meaning': 'Upstream test/syntax result only; no PHP Runtime Audit production-verdict authorization'
}
with open(out, 'w', encoding='utf-8') as f:
  json.dump(record, f, indent=2, sort_keys=True)
  f.write('\n')
print(f"Reuse evaluation {candidate}: {record['status']} (exit {status})")
PY
exit "$exit_code"
