<?php

declare(strict_types=1);

/**
 * Real-host, read-only evidence assertion for issue #16.
 * Runs on the ephemeral CI runner only; never prints raw facts, package versions
 * or process details. This script does not modify the audited system.
 */

use voku\PhpRuntimeAudit\Advisories\AdvisoryCatalog;
use voku\PhpRuntimeAudit\Advisories\AdvisoryEvaluator;
use voku\PhpRuntimeAudit\Advisories\RuntimeAuditReportBuilder;
use voku\PhpRuntimeAudit\RuntimeInventory\NetworkIsolation;
use voku\PhpRuntimeAudit\RuntimeInventory\ProcessCommand;
use voku\PhpRuntimeAudit\RuntimeInventory\RuntimeInventoryCollector;
use voku\PhpRuntimeAudit\RuntimeInventory\SystemProcessRunner;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

if (NetworkIsolation::currentNamespaceIsIsolated()) {
    throw new RuntimeException('Runner is already network-isolated; namespace-denied proof is not applicable.');
}

$runner = new SystemProcessRunner();
$attempt = $runner->run(ProcessCommand::DpkgPackages);
if ($attempt->succeeded() || $attempt->stdout !== '') {
    throw new RuntimeException('Expected dpkg executable evidence to be withheld under denied namespace creation.');
}

$inventory = (new RuntimeInventoryCollector($runner, '/'))->collect();
$facts = array_column($inventory['facts'], 'value', 'key');
$sources = array_column($inventory['sources'], null, 'locator');
$fileSource = $sources['file:/var/lib/dpkg/status'] ?? null;

if ($inventory['package_manager'] !== 'dpkg'
    || $inventory['package_inventory_state'] !== 'unknown'
    || $inventory['packages'] !== []
    || ($facts['packages.state'] ?? null) !== 'unknown'
    || ($facts['packages.file_observation.state'] ?? null) !== 'observed'
    || !is_array($fileSource)
    || !is_string($fileSource['captured_digest'] ?? null)
    || !str_starts_with($fileSource['captured_digest'], 'sha256:')) {
    throw new RuntimeException('File-only metadata must be separately observed without promoting package verification.');
}

$packageCount = $facts['packages.file_observation.package_count'] ?? null;
if (!is_int($packageCount) || $packageCount < 1 || $packageCount > 256) {
    throw new RuntimeException('Expected bounded installed PHP package metadata from the real dpkg status file.');
}

$fpmMetadataSeen = false;
for ($index = 0; $index < $packageCount; ++$index) {
    if (($facts['packages.file_observation.' . $index . '.name'] ?? null) === 'php8.3-fpm'
        && is_string($facts['packages.file_observation.' . $index . '.version'] ?? null)) {
        $fpmMetadataSeen = true;
    }
}
if (!$fpmMetadataSeen) {
    throw new RuntimeException('Real php8.3-fpm package is absent from the bounded file-only observation.');
}

$packageCoverageBlocked = false;
foreach ($inventory['coverage'] as $entry) {
    if ($entry['check_id'] === 'runtime.packages' && $entry['status'] === 'blocked') {
        $packageCoverageBlocked = true;
    }
}
if (!$packageCoverageBlocked || $inventory['workers'] === []) {
    throw new RuntimeException('Expected blocked package coverage and actual running FPM workers.');
}
foreach ($inventory['workers'] as $worker) {
    if ($worker['package_provenance']['verified'] !== false) {
        throw new RuntimeException('File-only metadata incorrectly became loaded-worker proof.');
    }
}

$evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());
$report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);
$assessments = array_filter($report['records'], static fn (array $record): bool => $record['record_type'] === 'assessment');
if ($assessments === [] || ($report['summary']['verdict_counts']['verified_fixed'] ?? null) !== 0) {
    throw new RuntimeException('Expected non-vacuous security assessments without verified_fixed verdicts.');
}
foreach ($assessments as $record) {
    if (($record['patch_status'] ?? null) !== 'unknown') {
        throw new RuntimeException('Package metadata must not establish a verified running-runtime patch status.');
    }
}

// Only bounded, non-sensitive aggregate evidence is emitted to the Actions log.
echo json_encode([
    'schema' => 1,
    'scenario' => 'real_ubuntu_fpm_namespace_creation_denied',
    'installed_fpm_worker_observed' => true,
    'dpkg_command_success' => false,
    'file_only_metadata_observed' => true,
    'file_metadata_digest_recorded' => true,
    'installed_php_package_count' => $packageCount,
    'assessments' => count($assessments),
    'verified_fixed' => 0,
    'loaded_worker_verified' => false,
    'patch_status' => 'unknown',
    'promotion_from_file_metadata' => false,
], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT), "\n";
