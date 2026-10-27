<?php

declare(strict_types=1);

try {
    if (!isset($argv[1], $argv[2]) || !in_array($argv[2], ['fpm', 'apache'], true)) {
        throw new RuntimeException('Expected a disposable report path and runtime kind.');
    }
    $json = file_get_contents($argv[1], false, null, 0, 1_048_577);
    if (!is_string($json) || strlen($json) > 1_048_576) {
        throw new RuntimeException('Disposable report is unreadable or oversized.');
    }
    $report = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
    if (!is_array($report) || ($report['report_schema_version'] ?? null) !== '1.0'
        || !is_array($report['summary'] ?? null) || !is_array($report['records'] ?? null)
        || ($report['summary']['container'] ?? null) !== true
        || !is_int($report['summary']['web_worker_count'] ?? null)
        || $report['summary']['web_worker_count'] < 1
        || ($report['summary']['compromise_evidence'] ?? null) !== 'unknown') {
        throw new RuntimeException('Expected a bounded container report with real web workers and separate compromise uncertainty.');
    }
    $expectedVersionPrefix = isset($argv[3]) && $argv[3] !== '' ? $argv[3] : null;
    $facts = [];
    $assessments = [];
    foreach ($report['records'] as $record) {
        if (!is_array($record)) {
            throw new RuntimeException('Invalid disposable record.');
        }
        if (($record['record_type'] ?? null) === 'observation' && is_array($record['facts'] ?? null)) {
            foreach ($record['facts'] as $fact) {
                if (is_array($fact) && is_string($fact['key'] ?? null)) {
                    $facts[$fact['key']] = $fact['value'] ?? null;
                }
            }
        }
        if (($record['record_type'] ?? null) === 'assessment') {
            if (($record['patch_status'] ?? null) === 'verified_fixed'
                || !is_array($record['compromise_evidence'] ?? null)
                || ($record['compromise_evidence']['status'] ?? null) !== 'unknown') {
                throw new RuntimeException('These source-built PHP images have no verified vendor-package provenance.');
            }
            $assessments[] = $record;
        }
    }
    $workerSeen = false;
    $fpmWorkerVersionMatches = $expectedVersionPrefix === null || $argv[2] !== 'fpm';
    $cliVersionMatches = $expectedVersionPrefix === null;
    $cliSeen = false;
    $moduleSeen = false;
    foreach ($facts as $key => $value) {
        if (preg_match('/^worker\.([0-9]+)\.kind$/D', $key, $matches) === 1 && $value === $argv[2]) {
            $workerSeen = true;
            if ($expectedVersionPrefix !== null && $argv[2] === 'fpm') {
                // FPM's own binary is invoked directly, so the collector records a full
                // dotted version (e.g. "8.2.35") in worker.N.version.
                $version = $facts['worker.' . $matches[1] . '.version'] ?? null;
                $fpmWorkerVersionMatches = $fpmWorkerVersionMatches
                    || (is_string($version) && str_starts_with($version, $expectedVersionPrefix));
            }
        }
        if (preg_match('/^runtime\.cli\.[0-9]+\.version$/D', $key) === 1 && is_string($value)) {
            $cliSeen = true;
            if ($expectedVersionPrefix !== null) {
                // A live Apache process cannot be asked its own PHP version the way FPM's binary
                // can (worker.N.version is intentionally left null for apache workers), and recent
                // official PHP images load an unversioned libphp.so with no version in the path at
                // all. Each container image has exactly one PHP installed, so the isolated CLI
                // probe's own dotted version is reliable evidence of which image actually ran,
                // for both kinds -- it's the primary check for apache, and corroborates the FPM
                // worker.N.version check above for fpm.
                $cliVersionMatches = $cliVersionMatches || str_starts_with($value, $expectedVersionPrefix);
            }
        }
        $moduleSeen = $moduleSeen || (str_ends_with($key, '.apache_php_modules') && is_array($value) && $value !== []);
    }
    if (!$workerSeen || !$cliSeen || ($argv[2] === 'apache' && !$moduleSeen) || $assessments === []) {
        throw new RuntimeException('Real worker, isolated CLI probe, or Apache module evidence is missing.');
    }
    if (!$fpmWorkerVersionMatches || !$cliVersionMatches) {
        throw new RuntimeException(sprintf(
            'Expected the audited %s container to report version evidence for %s; the inventory recorded something else. '
            . 'A passing disposable check must prove the pinned image version was actually audited, not merely that some worker ran.',
            $argv[2],
            $expectedVersionPrefix,
        ));
    }
    if ($argv[2] === 'fpm') {
        $setting = $facts['configuration.fpm.session.serialize_handler'] ?? null;
        $poolSeen = is_array($setting) && is_array($setting['files'] ?? null)
            && in_array('/usr/local/etc/php-fpm.d/zz-pra-fixture.conf', $setting['files'], true);
        $investigationSeen = false;
        foreach ($assessments as $assessment) {
            $investigationSeen = $investigationSeen || (is_string($assessment['record_id'] ?? null)
                && str_contains($assessment['record_id'], 'CVE-2026-115560')
                && ($assessment['verdict'] ?? null) === 'needs_investigation'
                && ($assessment['patch_status'] ?? null) === 'unknown');
        }
        if (!$poolSeen || !$investigationSeen) {
            throw new RuntimeException('Official FPM pool override was omitted or its operational risk was conflated with patch status.');
        }
    }
    echo $argv[2], ' (audited-runtime-version ', $expectedVersionPrefix ?? 'unpinned', '*): ',
    'real worker/CLI evidence and vendor uncertainty verified; ',
    (string) $report['summary']['web_worker_count'], " workers.\n";
} catch (Throwable $error) {
    fwrite(STDERR, 'Disposable runtime check failed: ' . $error->getMessage() . "\n");
    exit(1);
}
