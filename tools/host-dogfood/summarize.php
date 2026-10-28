<?php

declare(strict_types=1);

// Report only aggregate coverage. Never publish the raw host inventory,
// process arguments, paths, package versions or remediation instructions.
if (count($argv) !== 3) {
    fwrite(STDERR, "Expected two local JSON report paths.\n");
    exit(2);
}

$inventory = json_decode((string) file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);
$plan = json_decode((string) file_get_contents($argv[2]), true, 512, JSON_THROW_ON_ERROR);
if (!is_array($inventory) || !is_array($plan)
    || !array_is_list($inventory['records'] ?? null)
    || !array_is_list($plan['actions'] ?? null)
    || ($plan['automatic_apply'] ?? null) !== false) {
    throw new RuntimeException('Unexpected report format or unsafe automatic_apply flag.');
}
foreach ($plan['actions'] as $action) {
    if (!is_array($action) || ($action['requires_human_approval'] ?? null) !== true) {
        throw new RuntimeException('A proposed action does not require human approval.');
    }
}

$attempted = 0;
$blocked = 0;
$blockedChecks = [];
foreach ($inventory['records'] as $record) {
    if (($record['record_type'] ?? null) !== 'coverage') {
        continue;
    }
    foreach (($record['entries'] ?? []) as $entry) {
        $attempted += (int) (($entry['status'] ?? null) === 'attempted');
        $blocked += (int) (($entry['status'] ?? null) === 'blocked');
        if (($entry['status'] ?? null) === 'blocked') {
            $checkId = $entry['check_id'] ?? null;
            // Emit only pre-reviewed, stable identifiers, not free-text gaps.
            if (is_string($checkId) && in_array($checkId, [
                'runtime.cli', 'runtime.packages', 'runtime.workers',
                'runtime.configuration', 'runtime.discovery',
                'advisory.assessment_targets',
            ], true)) {
                $blockedChecks[] = $checkId;
            }
        }
    }
}

$summary = $inventory['summary'] ?? null;
if (!is_array($summary) || ($inventory['report_schema_version'] ?? null) !== '1.0') {
    throw new RuntimeException('Missing expected versioned inventory summary.');
}
$counts = $summary['verdict_counts'] ?? null;
if (!is_array($counts)) {
    throw new RuntimeException('Missing verdict counts.');
}
$allowedVerdicts = ['unknown', 'verified_fixed', 'potentially_affected', 'needs_investigation'];
foreach ($counts as $key => $count) {
    if (!in_array($key, $allowedVerdicts, true) || !is_int($count)) {
        throw new RuntimeException('Unexpected verdict category/count.');
    }
}

$result = [
    'schema_version' => 1,
    'environment' => 'ephemeral_github_hosted_ubuntu_24_04',
    'installed_fpm' => true,
    'test_type' => 'real_host_live_proc_and_dpkg_not_container_fixture',
    'report_generated' => true,
    'record_count' => count($inventory['records']),
    'web_worker_count' => $summary['web_worker_count'] ?? null,
    'assessment_count' => $summary['assessment_count'] ?? null,
    'coverage_attempted' => $attempted,
    'coverage_blocked' => $blocked,
    'blocked_check_ids' => array_values(array_unique($blockedChecks)),
    'namespace_creation_supported' => match (getenv('PRA_NAMESPACE_SUPPORTED')) {
        'yes' => true,
        'no' => false,
        default => null,
    },
    'verdict_counts' => $counts,
    'automatic_apply' => false,
    'human_approval_required_for_every_action' => true,
    'compromise_evidence' => $summary['compromise_evidence'] ?? 'unknown',
    'operator_follow_up_required' => true,
    'note' => 'Actual ephemeral runner; not an independent proof for a private production host.',
];
echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
