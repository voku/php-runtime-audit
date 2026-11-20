<?php

declare(strict_types=1);

/*
 * Asserts the session-store results of one disposable real-worker scenario (issue #38 slice 4).
 *
 * Usage: php assert-disposable-session-report.php <report.json> <scenario> [<remediation-plan.json>]
 *
 * Expectations are deliberately conservative: configuration evidence may raise an investigation,
 * but nothing here may ever look patched (these source-built images have no vendor provenance),
 * compromise stays unknown, and the fixture credential must never appear in any output.
 */

const FIXTURE_SECRETS = ['PRA-FIXTURE-SECRET', '10.9.8.7', 'auth='];

/**
 * scenario => [runtime kind, CVE-2026-115560 verdict, 115560 exposure, 126714 exposure, rationale needle|null, redacted save_path scheme|null]
 *
 * @var array<string, array{string, string, string, string, string|null, string|null}>
 */
const SCENARIOS = [
    // Writer pool enables upload progress with php, reader pool decodes the same explicit store
    // with php_serialize: only the shared-store correlation can see this.
    'fpm-shared-store-mismatch' => ['fpm', 'needs_investigation', 'needs_investigation', 'unknown', 'configure the same session store', null],
    // Same serializer split, but each pool has its own store.
    'fpm-isolated-stores' => ['fpm', 'unknown', 'unknown', 'unknown', null, null],
    // Shared store, identical serializers: no mismatch to report.
    'fpm-shared-store-same-serializer' => ['fpm', 'unknown', 'unknown', 'unknown', null, null],
    // Missing evidence stays unknown; PHP's implicit defaults are never treated as observations.
    'fpm-no-session-config' => ['fpm', 'unknown', 'unknown', 'unknown', null, null],
    // Administratively disabled upload progress is a mitigation, not a patch claim.
    'fpm-upload-progress-disabled' => ['fpm', 'unknown', 'not_observed', 'unknown', null, null],
    // The affected files backend is configured: investigate CVE-2026-126714 exposure.
    'fpm-files-backend' => ['fpm', 'unknown', 'not_observed', 'needs_investigation', null, null],
    // A non-files backend can never rule CVE-2026-126714 out (applications may register their
    // own handler), and the credential-bearing DSN is only kept as a redacted store identity.
    'fpm-redis-dsn' => ['fpm', 'unknown', 'unknown', 'unknown', null, 'tcp'],
    // The official Apache image loads an unversioned libphp.so without package provenance, so
    // the loaded module cannot be tied to a configuration root: exposure stays unknown even with
    // the files backend configured, and the DSN is still redacted.
    'apache-files-backend-redacted-dsn' => ['apache', 'unknown', 'unknown', 'unknown', null, 'tcp'],
];

/** @return array<mixed> */
function readJsonFile(string $path): array
{
    $json = file_get_contents($path, false, null, 0, 1_048_577);
    if (!is_string($json) || strlen($json) > 1_048_576) {
        throw new RuntimeException('Disposable JSON output is unreadable or oversized: ' . $path);
    }
    foreach (FIXTURE_SECRETS as $secret) {
        if (str_contains($json, $secret)) {
            throw new RuntimeException('A fixture credential or backend host leaked into ' . basename($path) . '.');
        }
    }
    $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
    if (!is_array($data)) {
        throw new RuntimeException('Disposable JSON output is not an object: ' . $path);
    }

    return $data;
}

/** @param array<string, mixed> $exposure */
function exposureState(array $exposure): string
{
    return is_string($exposure['state'] ?? null) ? $exposure['state'] : '';
}

try {
    if (!isset($argv[1], $argv[2]) || !array_key_exists($argv[2], SCENARIOS)) {
        throw new RuntimeException('Expected a disposable report path and a known session scenario.');
    }
    [$kind, $expectedVerdict, $expected115560Exposure, $expected126714Exposure, $rationaleNeedle, $redactedScheme] = SCENARIOS[$argv[2]];
    $report = readJsonFile($argv[1]);
    if (($report['report_schema_version'] ?? null) !== '1.0' || !is_array($report['records'] ?? null)
        || !is_array($report['summary'] ?? null) || ($report['summary']['container'] ?? null) !== true
        || ($report['summary']['compromise_evidence'] ?? null) !== 'unknown') {
        throw new RuntimeException('Expected a bounded container report with separate compromise uncertainty.');
    }

    /** @var array<string, mixed> $facts */
    $facts = [];
    /** @var array<string, true> $factIds */
    $factIds = [];
    /** @var list<array<mixed>> $assessments */
    $assessments = [];
    foreach ($report['records'] as $record) {
        if (!is_array($record)) {
            throw new RuntimeException('Invalid disposable record.');
        }
        foreach (is_array($record['facts'] ?? null) ? $record['facts'] : [] as $fact) {
            if (is_array($fact) && is_string($fact['key'] ?? null)) {
                $facts[$fact['key']] = $fact['value'] ?? null;
                if (is_string($fact['fact_id'] ?? null)) {
                    $factIds[$fact['fact_id']] = true;
                }
            }
        }
        if (($record['record_type'] ?? null) === 'assessment') {
            if (in_array($record['patch_status'] ?? null, ['verified_fixed'], true)
                || ($record['verdict'] ?? null) === 'verified_fixed'
                || !is_array($record['compromise_evidence'] ?? null)
                || ($record['compromise_evidence']['status'] ?? null) !== 'unknown') {
                throw new RuntimeException('Source-built images must never look patched, and compromise must stay unknown.');
            }
            $assessments[] = $record;
        }
    }

    // The audited web target: the versioned FPM master, or the first Apache module target.
    $targetId = null;
    $subjectPrefix = null;
    foreach ($facts as $key => $value) {
        if ($kind === 'fpm' && preg_match('/^worker\.([0-9]+)\.kind$/D', $key, $matches) === 1 && $value === 'fpm'
            && is_string($facts['worker.' . $matches[1] . '.version'] ?? null)
            && is_string($facts['worker.' . $matches[1] . '.id'] ?? null)) {
            $targetId = 'worker-' . $matches[1];
            $subjectPrefix = $facts['worker.' . $matches[1] . '.id'];
            break;
        }
        if ($kind === 'apache' && preg_match('/^advisory\.CVE-2026-115560\.(apache-[0-9]+-[0-9a-z]+-1)\.configuration_exposure$/D', $key, $matches) === 1) {
            $targetId = $matches[1];
            $subjectPrefix = $matches[1];
            break;
        }
    }
    if ($targetId === null || $subjectPrefix === null) {
        throw new RuntimeException('No audited ' . $kind . ' web target was found in the report.');
    }

    $assessmentFor = static function (string $cve, string $subjectPrefix) use ($assessments): array {
        foreach ($assessments as $assessment) {
            if (is_string($assessment['record_id'] ?? null) && str_starts_with($assessment['record_id'], 'assessment:' . $cve . ':')
                && is_string($assessment['subject_id'] ?? null) && $assessment['subject_id'] === $subjectPrefix) {
                return $assessment;
            }
        }
        throw new RuntimeException('Missing ' . $cve . ' assessment for ' . $subjectPrefix . '.');
    };
    $exposureFor = static function (string $cve, string $targetId) use ($facts): array {
        $value = $facts['advisory.' . $cve . '.' . $targetId . '.configuration_exposure'] ?? null;
        if (!is_array($value) || !is_array($value['independent_of'] ?? null)) {
            throw new RuntimeException('Missing ' . $cve . ' configuration_exposure fact for ' . $targetId . '.');
        }
        /** @var array<string, mixed> $value */
        return $value;
    };

    $assessment = $assessmentFor('CVE-2026-115560', $subjectPrefix);
    if (($assessment['verdict'] ?? null) !== $expectedVerdict) {
        throw new RuntimeException(sprintf('CVE-2026-115560 verdict for %s: expected %s, got %s.', $argv[2], $expectedVerdict, json_encode($assessment['verdict'] ?? null)));
    }
    if ($rationaleNeedle !== null
        && (!is_string($assessment['rationale'] ?? null) || !str_contains($assessment['rationale'], $rationaleNeedle))) {
        throw new RuntimeException('CVE-2026-115560 rationale does not explain the scenario: ' . $argv[2]);
    }
    foreach ([['CVE-2026-115560', $expected115560Exposure], ['CVE-2026-126714', $expected126714Exposure]] as [$cve, $expectedState]) {
        $state = exposureState($exposureFor($cve, $targetId));
        if ($state !== $expectedState) {
            throw new RuntimeException(sprintf('%s exposure for %s: expected %s, got %s.', $cve, $argv[2], $expectedState, $state));
        }
    }
    // CVE-2026-126714's verdict is patch-driven only; without vendor provenance it stays unknown.
    if (($assessmentFor('CVE-2026-126714', $subjectPrefix)['verdict'] ?? null) !== 'unknown') {
        throw new RuntimeException('CVE-2026-126714 verdict must stay patch-driven (unknown) for ' . $argv[2] . '.');
    }
    // Mixed CLI/web settings: the CLI subject never inherits a web pool's configuration risk.
    foreach ($assessments as $candidate) {
        if (is_string($candidate['subject_id'] ?? null) && str_starts_with($candidate['subject_id'], 'cli-')
            && ($candidate['verdict'] ?? null) === 'needs_investigation') {
            throw new RuntimeException('A CLI subject inherited web configuration risk in ' . $argv[2] . '.');
        }
    }
    if ($redactedScheme !== null) {
        $sapi = $kind === 'fpm' ? 'fpm' : 'apache2';
        $savePath = $facts['configuration.' . $sapi . '.session.save_path'] ?? null;
        $observed = is_array($savePath) && is_array($savePath['observations'] ?? null) ? $savePath['observations'] : [];
        $redacted = array_filter(
            $observed,
            static fn(mixed $observation): bool => is_array($observation) && is_string($observation['value'] ?? null)
                && preg_match('/\Aredacted:' . preg_quote($redactedScheme, '/') . ':[0-9a-f]{16}\z/', $observation['value']) === 1,
        );
        if ($redacted === []) {
            throw new RuntimeException('The credential-bearing save_path was not kept as a redacted store identity in ' . $argv[2] . '.');
        }
    }

    if (isset($argv[3])) {
        // inventory -> report -> remediation: the raised finding becomes a human-gated
        // configuration investigation whose evidence ids all exist in the report.
        $plan = readJsonFile($argv[3]);
        $found = false;
        foreach (is_array($plan['actions'] ?? null) ? $plan['actions'] : [] as $action) {
            if (!is_array($action) || ($action['cve'] ?? null) !== 'CVE-2026-115560' || ($action['subject_id'] ?? null) !== $subjectPrefix) {
                continue;
            }
            if (($action['kind'] ?? null) !== 'investigate_configuration' || ($action['requires_human_approval'] ?? null) !== true
                || !is_array($action['evidence_ids'] ?? null) || $action['evidence_ids'] === []) {
                throw new RuntimeException('The remediation action is not a human-gated configuration investigation with evidence.');
            }
            foreach ($action['evidence_ids'] as $evidenceId) {
                if (!is_string($evidenceId) || !isset($factIds[$evidenceId])) {
                    throw new RuntimeException('Remediation evidence id is not present in the report: ' . json_encode($evidenceId));
                }
            }
            $found = true;
        }
        if (!$found || ($plan['automatic_apply'] ?? null) !== false) {
            throw new RuntimeException('Expected a non-automatic remediation action for the audited worker.');
        }
    }

    echo $argv[2], ' (', $kind, '): session-store verdicts, exposure facts, redaction and compromise uncertainty verified',
    isset($argv[3]) ? '; remediation plan cross-checked' : '', ".\n";
} catch (Throwable $error) {
    fwrite(STDERR, 'Disposable session check failed: ' . $error->getMessage() . "\n");
    exit(1);
}
