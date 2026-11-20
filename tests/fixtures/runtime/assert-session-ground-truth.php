<?php

declare(strict_types=1);

/*
 * Validates the audit against ground truth for one disposable two-pool FPM scenario (issue #38).
 *
 * Usage: php assert-session-ground-truth.php <report.json> <ground-truth.json>
 *
 * The ground truth comes from real requests to the scenario's writer and reader pools: whether
 * the writer's session file appeared in the reader's live save_path before the reader touched it
 * (a genuinely shared store), and whether the reader could decode it. The audit's CVE-2026-115560
 * shared-store finding must be raised exactly when the store is shared and the reader cannot
 * decode the writer's data -- no more (false alarm) and no less (missed exposure).
 */

/** @return array<mixed> */
function readJson(string $path): array
{
    $json = file_get_contents($path, false, null, 0, 1_048_577);
    if (!is_string($json) || strlen($json) > 1_048_576) {
        throw new RuntimeException('Unreadable or oversized JSON: ' . $path);
    }
    $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
    if (!is_array($data)) {
        throw new RuntimeException('Expected a JSON object: ' . $path);
    }

    return $data;
}

const SHARED_STORE_PHRASES = ['configure the same session store', 'appear to share one default session location'];

try {
    if (!isset($argv[1], $argv[2])) {
        throw new RuntimeException('Expected a report path and a ground-truth path.');
    }
    $report = readJson($argv[1]);
    $truth = readJson($argv[2]);
    foreach (['writer_read_back', 'shared_store', 'reader_started', 'reader_decodes'] as $key) {
        if (!is_bool($truth[$key] ?? null)) {
            throw new RuntimeException('Ground truth is missing ' . $key . '.');
        }
    }
    if ($truth['writer_read_back'] !== true) {
        throw new RuntimeException('The writer pool did not persist the probe session to its own live store; ground truth is unusable.');
    }
    if ($truth['reader_decodes'] === true && $truth['shared_store'] !== true) {
        throw new RuntimeException('The reader decoded a session it cannot see; ground truth is inconsistent.');
    }
    // An isolated store is only proven by a healthy reader that started and did not see the writer's value.
    if ($truth['shared_store'] === false && $truth['reader_started'] !== true) {
        throw new RuntimeException('The reader could not start a session in its own store; an isolated-store result is unusable as ground truth.');
    }
    // "Cannot decode" must be a real decode failure, not a permission, locking or I/O problem.
    $readerError = is_string($truth['reader_start_error'] ?? null) ? $truth['reader_start_error'] : '';
    if ($truth['shared_store'] === true && $truth['reader_decodes'] === false
        && !str_contains($readerError, 'Failed to decode session object')) {
        throw new RuntimeException('The reader could not read a shared session for a reason other than decoding (' . ($readerError === '' ? 'no error reported' : $readerError) . '); ground truth is unusable.');
    }

    $facts = [];
    $assessments = [];
    foreach (is_array($report['records'] ?? null) ? $report['records'] : [] as $record) {
        if (!is_array($record)) {
            continue;
        }
        foreach (is_array($record['facts'] ?? null) ? $record['facts'] : [] as $fact) {
            if (is_array($fact) && is_string($fact['key'] ?? null)) {
                $facts[$fact['key']] = $fact['value'] ?? null;
            }
        }
        if (($record['record_type'] ?? null) === 'assessment') {
            $assessments[] = $record;
        }
    }
    $subject = null;
    foreach ($facts as $key => $value) {
        if (preg_match('/^worker\.([0-9]+)\.kind$/D', $key, $matches) === 1 && $value === 'fpm'
            && is_string($facts['worker.' . $matches[1] . '.version'] ?? null)
            && is_string($facts['worker.' . $matches[1] . '.id'] ?? null)) {
            $subject = $facts['worker.' . $matches[1] . '.id'];
            break;
        }
    }
    if ($subject === null) {
        throw new RuntimeException('No versioned FPM worker was found in the report.');
    }
    $assessment = null;
    foreach ($assessments as $candidate) {
        if (($candidate['subject_id'] ?? null) === $subject && is_string($candidate['record_id'] ?? null)
            && str_starts_with($candidate['record_id'], 'assessment:CVE-2026-115560:')) {
            $assessment = $candidate;
        }
    }
    if ($assessment === null || !is_string($assessment['rationale'] ?? null)) {
        throw new RuntimeException('Missing CVE-2026-115560 assessment for ' . $subject . '.');
    }
    $raised = in_array($assessment['verdict'] ?? null, ['needs_investigation', 'potentially_affected'], true)
        && array_filter(SHARED_STORE_PHRASES, static fn(string $phrase): bool => str_contains($assessment['rationale'], $phrase)) !== [];
    $exposed = $truth['shared_store'] && !$truth['reader_decodes'];
    if ($raised !== $exposed) {
        throw new RuntimeException(sprintf(
            'Audit disagrees with ground truth: shared-store finding %s, but the store is %s and the reader %s the writer\'s session.',
            $raised ? 'raised' : 'not raised',
            $truth['shared_store'] ? 'shared' : 'not shared',
            $truth['reader_decodes'] ? 'decodes' : 'cannot decode',
        ));
    }

    printf(
        "ground truth: store %s, reader %s -> shared-store finding %s, matching the audit.\n",
        $truth['shared_store'] ? 'shared' : 'isolated',
        $truth['reader_decodes'] ? 'decodes' : 'cannot decode',
        $raised ? 'raised' : 'not raised',
    );
} catch (Throwable $error) {
    fwrite(STDERR, 'Session ground-truth validation failed: ' . $error->getMessage() . "\n");
    exit(1);
}
