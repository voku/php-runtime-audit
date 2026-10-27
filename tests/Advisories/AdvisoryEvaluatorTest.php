<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\Advisories;

use PHPUnit\Framework\TestCase;
use voku\PhpRuntimeAudit\Advisories\AdvisoryCatalog;
use voku\PhpRuntimeAudit\Advisories\AdvisoryEvaluator;
use voku\PhpRuntimeAudit\Advisories\RuntimeAuditReportBuilder;
use voku\PhpRuntimeAudit\RuntimeInventory\FixtureProcessRunner;
use voku\PhpRuntimeAudit\RuntimeInventory\RuntimeInventoryCollector;

/**
 * @phpstan-import-type RuntimeInventory from RuntimeInventoryCollector
 * @phpstan-import-type AdvisoryEvaluation from AdvisoryEvaluator
 * @phpstan-import-type AdvisoryAssessment from AdvisoryEvaluator
 * @phpstan-import-type RuntimeAuditReport from RuntimeAuditReportBuilder
 */
final class AdvisoryEvaluatorTest extends TestCase
{
    public function test_installed_debian_fixed_build_without_worker_integrity_stays_unknown(): void
    {
        [$inventory, $evaluation] = $this->evaluate('debian-fpm');
        $assessment = $this->assessmentMap($evaluation);

        self::assertSame('unknown', $assessment['CVE-2026-109618']['patch_status']);
        self::assertSame('unknown', $assessment['CVE-2026-109619']['patch_status']);
        self::assertSame('unknown', $assessment['CVE-2026-115560']['patch_status']);
        self::assertSame('unknown', $assessment['CVE-2026-115560']['verdict']);
        self::assertSame('unknown', $assessment['CVE-2026-109618']['compromise_evidence']['status']);

        /** @var RuntimeAuditReport $report */
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);
        self::assertSame(12, $report['summary']['assessment_count']);
        self::assertSame(5, $report['summary']['coverage_count']);
        self::assertSame('unknown', $report['summary']['compromise_evidence']);
        self::assertSame('coverage', $report['records'][1]['record_type']);
    }

    public function test_cli_fixed_version_does_not_override_vulnerable_running_fpm(): void
    {
        [, $evaluation] = $this->evaluate('debian-fpm-vulnerable');
        $assessment = $this->assessmentMap($evaluation);

        self::assertSame('potentially_affected', $assessment['CVE-2026-109618']['patch_status']);
        self::assertSame('potentially_affected', $assessment['CVE-2026-109619']['patch_status']);
        self::assertStringContainsString('Runtime: 8.2.34.', $assessment['CVE-2026-109618']['rationale']);
    }

    public function test_unknown_rhel_family_backport_status_stays_unknown(): void
    {
        [, $evaluation] = $this->evaluate('rocky9-fpm');
        $assessment = $this->assessmentMap($evaluation);

        self::assertSame('unknown', $assessment['CVE-2026-109618']['patch_status']);
        self::assertSame('unknown', $assessment['CVE-2026-109619']['patch_status']);
    }

    public function test_remi_cli_and_fpm_packages_keep_distinct_runtime_subjects_with_unknown_vendor_status(): void
    {
        $inventory = $this->collectInventory('debian-fpm');
        $cliPath = '/opt/remi/php74/root/usr/bin/php';
        $cliId = 'cli-' . substr(hash('sha256', $cliPath), 0, 20);
        $fpmPath = '/opt/remi/php74/root/usr/sbin/php-fpm';
        $workerId = $inventory['workers'][0]['id'];

        $inventory['runtimes'][0]['id'] = $cliId;
        $inventory['runtimes'][0]['binary_path'] = $cliPath;
        $inventory['runtimes'][0]['version'] = '7.4.33';
        $inventory['workers'][0]['executable_path'] = $fpmPath;
        $inventory['workers'][0]['version'] = '7.4.33';
        $inventory['workers'][0]['package_provenance'] = \voku\PhpRuntimeAudit\RuntimeInventory\RuntimePackageProvenance::unknown('unsupported_package_integrity');
        $inventory['packages'] = [
            ['name' => 'php74-php-cli', 'version' => '7.4.33-1.el9.remi'],
            ['name' => 'php74-php-fpm', 'version' => '7.4.33-1.el9.remi'],
        ];
        foreach ($inventory['facts'] as &$fact) {
            if ($fact['key'] === 'runtime.cli.1.id') {
                $fact['value'] = $cliId;
            } elseif ($fact['key'] === 'runtime.cli.1.binary_path') {
                $fact['value'] = $cliPath;
            } elseif ($fact['key'] === 'runtime.cli.1.version') {
                $fact['value'] = '7.4.33';
            } elseif ($fact['key'] === 'worker.1.executable_path') {
                $fact['value'] = $fpmPath;
            } elseif ($fact['key'] === 'worker.1.version') {
                $fact['value'] = '7.4.33';
            }
        }
        unset($fact);

        [, $evaluation] = $this->evaluateInventory($inventory);
        $bySubject = [];
        foreach ($evaluation['assessments'] as $assessment) {
            $bySubject[$assessment['subject_id']] = $assessment;
        }
        $cliPackageId = 'package-' . substr(hash('sha256', "php74-php-cli\0" . '7.4.33-1.el9.remi'), 0, 20);
        $fpmPackageId = 'package-' . substr(hash('sha256', "php74-php-fpm\0" . '7.4.33-1.el9.remi'), 0, 20);

        foreach ([$cliId, $workerId, $cliPackageId, $fpmPackageId] as $subjectId) {
            self::assertArrayHasKey($subjectId, $bySubject);
            self::assertSame('unknown', $bySubject[$subjectId]['patch_status']);
        }
        self::assertStringContainsString('Package: php74-php-cli 7.4.33-1.el9.remi.', $bySubject[$cliId]['rationale']);
        self::assertStringContainsString('Package: php74-php-fpm 7.4.33-1.el9.remi.', $bySubject[$workerId]['rationale']);
    }

    public function test_exact_alpine_vendor_build_without_worker_integrity_stays_unknown(): void
    {
        [, $evaluation] = $this->evaluate('alpine-fpm');
        $assessment = $this->assessmentMap($evaluation);

        self::assertSame('unknown', $assessment['CVE-2026-109618']['patch_status']);
        self::assertSame('unknown', $assessment['CVE-2026-109619']['patch_status']);
    }

    public function test_inconsistent_proc_identity_keeps_alpine_worker_patch_status_unknown(): void
    {
        [, $evaluation] = $this->evaluate('alpine-fpm-mismatched-process');
        $assessment = $this->assessmentMap($evaluation);

        self::assertSame('unknown', $assessment['CVE-2026-109618']['patch_status']);
        self::assertSame('unknown', $assessment['CVE-2026-109619']['patch_status']);
    }

    public function test_process_version_disagreement_with_fpm_executable_cannot_be_verified_fixed(): void
    {
        [, $evaluation] = $this->evaluate('debian-fpm-process-executable-mismatch');
        $assessment = $this->assessmentMap($evaluation);

        self::assertSame('unknown', $assessment['CVE-2026-109618']['patch_status']);
        self::assertSame('unknown', $assessment['CVE-2026-109619']['patch_status']);
    }

    public function test_exact_rhel10_errata_build_without_worker_integrity_stays_unknown(): void
    {
        [, $evaluation] = $this->evaluate('rhel10-fpm');
        $assessment = $this->assessmentMap($evaluation);

        self::assertSame('unknown', $assessment['CVE-2026-109618']['patch_status']);
        self::assertSame('unknown', $assessment['CVE-2026-109619']['patch_status']);
    }

    public function test_rhel_fpm_pool_override_requires_investigation_but_does_not_change_patch_status(): void
    {
        [, $evaluation] = $this->evaluate('rhel10-fpm-pool-override');
        $assessment = $this->assessmentMap($evaluation)['CVE-2026-115560'];

        self::assertSame('needs_investigation', $assessment['verdict']);
        self::assertSame('unknown', $assessment['patch_status']);
        self::assertSame('unknown', $assessment['compromise_evidence']['status']);
        self::assertStringContainsString('precedence', $assessment['rationale']);
    }

    public function test_unverified_source_container_version_stays_unknown_without_package_provenance(): void
    {
        [, $evaluation] = $this->evaluate('container-fpm');
        $assessment = $this->assessmentMap($evaluation);

        self::assertSame('unknown', $assessment['CVE-2026-109618']['patch_status']);
        self::assertSame('unknown', $assessment['CVE-2026-109619']['patch_status']);
        self::assertStringContainsString('does not establish package provenance', $assessment['CVE-2026-109618']['rationale']);
        self::assertSame('unknown', $assessment['CVE-2026-115560']['verdict']);
    }

    public function test_duplicate_package_versions_and_conflicting_distribution_identity_stay_unknown(): void
    {
        $inventory = $this->collectInventory('debian-fpm');
        $inventory['packages'][] = ['name' => 'php8.2-fpm', 'version' => '8.2.34-1~deb12u1'];
        [, $duplicateEvaluation] = $this->evaluateInventory($inventory);
        $duplicate = $this->assessmentMap($duplicateEvaluation);

        $inventory = $this->collectInventory('debian-fpm');
        $inventory['distribution_version'] = '13';
        foreach ($inventory['facts'] as &$fact) {
            if ($fact['key'] === 'os.version_id') {
                $fact['value'] = '13';
            }
        }
        unset($fact);
        [, $releaseConflictEvaluation] = $this->evaluateInventory($inventory);
        $releaseConflict = $this->assessmentMap($releaseConflictEvaluation);

        $inventory = $this->collectInventory('debian-fpm');
        $inventory['package_manager'] = 'rpm';
        [, $managerConflictEvaluation] = $this->evaluateInventory($inventory);
        $managerConflict = $this->assessmentMap($managerConflictEvaluation);

        self::assertSame('unknown', $duplicate['CVE-2026-109618']['patch_status']);
        self::assertSame('unknown', $releaseConflict['CVE-2026-109618']['patch_status']);
        self::assertSame('unknown', $managerConflict['CVE-2026-109618']['patch_status']);
    }

    public function test_newer_vendor_package_without_an_exact_catalog_rule_stays_unknown(): void
    {
        $inventory = $this->collectInventory('debian-fpm');
        foreach ($inventory['workers'] as &$worker) {
            if ($worker['kind'] === 'fpm') {
                $worker['version'] = '8.2.36';
            }
        }
        unset($worker);
        /** @var list<array{name: string, version: string}> $packages */
        $packages = $inventory['packages'];
        foreach ($packages as &$package) {
            if ($package['name'] === 'php8.2-fpm') {
                $package['version'] = '8.2.36-1~deb12u1';
            }
        }
        unset($package);
        $inventory['packages'] = $packages;
        /** @var list<array{fact_id: string, key: string, value: mixed, source_id: string}> $facts */
        $facts = $inventory['facts'];
        foreach ($facts as &$fact) {
            if ($fact['key'] === 'worker.1.version') {
                $fact['value'] = '8.2.36';
            }
            if ($fact['key'] === 'package.1.version') {
                $fact['value'] = '8.2.36-1~deb12u1';
            }
        }
        unset($fact);
        $inventory['facts'] = $facts;
        [, $evaluation] = $this->evaluateInventory($inventory);

        self::assertSame('unknown', $this->assessmentMap($evaluation)['CVE-2026-109618']['patch_status']);
    }

    public function test_apache_package_fix_does_not_prove_loaded_module_was_restarted(): void
    {
        [, $evaluation] = $this->evaluate('ubuntu-apache');
        $assessment = $this->assessmentMap($evaluation);

        self::assertSame('unknown', $assessment['CVE-2026-109618']['patch_status']);
        self::assertSame('unknown', $assessment['CVE-2026-109619']['patch_status']);
        self::assertStringContainsString('runtime version is unknown', $assessment['CVE-2026-109618']['rationale']);
    }

    public function test_apache_risk_configuration_requests_investigation_without_claiming_a_fix(): void
    {
        [, $evaluation] = $this->evaluate('ubuntu-apache');
        $assessment = $this->assessmentMap($evaluation)['CVE-2026-115560'];

        self::assertSame('needs_investigation', $assessment['verdict']);
        self::assertSame('unknown', $assessment['patch_status']);
    }

    public function test_deleted_fpm_worker_and_package_runtime_conflict_stay_unknown(): void
    {
        [, $deletedEvaluation] = $this->evaluate('deleted-worker');
        [, $conflictEvaluation] = $this->evaluate('debian-fpm-runtime-conflict');

        self::assertSame('unknown', $this->assessmentMap($deletedEvaluation)['CVE-2026-109618']['patch_status']);
        self::assertSame('unknown', $this->assessmentMap($conflictEvaluation)['CVE-2026-109618']['patch_status']);
    }

    public function test_cve_115560_suspicious_config_requests_investigation_from_suspicious_observations(): void
    {
        [, $suspiciousEvaluation] = $this->evaluate('cve115560-config');
        [, $conflictingEvaluation] = $this->evaluate('configuration-conflict');
        $suspicious = $this->assessmentMap($suspiciousEvaluation)['CVE-2026-115560'];
        $conflicting = $this->assessmentMap($conflictingEvaluation)['CVE-2026-115560'];

        self::assertSame('needs_investigation', $suspicious['verdict']);
        self::assertSame('unknown', $suspicious['patch_status']);
        self::assertSame('needs_investigation', $conflicting['verdict']);
        self::assertSame('unknown', $conflicting['patch_status']);
        self::assertStringContainsString('precedence', $conflicting['rationale']);
    }

    public function test_patch_advisory_applicability_requires_verified_vendor_runtime_evidence(): void
    {
        $vulnerableInventory = $this->collectInventory('synthetic-debian-integrity');
        $vulnerableInventory['workers'][0]['version'] = '8.2.34';
        $vulnerableInventory['workers'][0]['package_provenance']['package_version'] = '8.2.34-1~deb12u1';
        foreach ($vulnerableInventory['packages'] as &$package) {
            if ($package['name'] === 'php8.2-fpm') {
                $package['version'] = '8.2.34-1~deb12u1';
            }
        }
        unset($package);
        foreach ($vulnerableInventory['facts'] as &$fact) {
            $key = $fact['key'] ?? null;
            if ($key === 'worker.1.version') {
                $fact['value'] = '8.2.34';
            }
            if ($key === 'package.1.version') {
                $fact['value'] = '8.2.34-1~deb12u1';
            }
        }
        unset($fact);
        [, $vulnerableEvaluation] = $this->evaluateInventory($vulnerableInventory);
        [, $fixedEvaluation] = $this->evaluate('synthetic-debian-integrity');
        [, $unverifiedEvaluation] = $this->evaluate('debian-fpm');
        $vulnerableFacts = $this->factMap($vulnerableEvaluation);
        $fixedFacts = $this->factMap($fixedEvaluation);
        $unverifiedFacts = $this->factMap($unverifiedEvaluation);

        self::assertSame('true', $vulnerableFacts['advisory.CVE-2026-109618.worker-1.applicability']);
        self::assertSame('true', $vulnerableFacts['advisory.CVE-2026-109619.worker-1.applicability']);
        self::assertSame('false', $fixedFacts['advisory.CVE-2026-109618.worker-1.applicability']);
        self::assertSame('false', $fixedFacts['advisory.CVE-2026-109619.worker-1.applicability']);
        self::assertSame('unknown', $unverifiedFacts['advisory.CVE-2026-109618.worker-1.applicability']);
        self::assertSame('unknown', $unverifiedFacts['advisory.CVE-2026-109619.worker-1.applicability']);
    }

    public function test_cve_115560_applicability_keeps_runtime_application_condition_unknown(): void
    {
        [, $inactiveEvaluation] = $this->evaluate('debian-fpm');
        [, $configurationEvaluation] = $this->evaluate('cve115560-config');
        $otherSerializerInventory = $this->collectInventory('cve115560-config');
        $otherSerializer = &$otherSerializerInventory['configuration_by_sapi']['fpm']['session.serialize_handler'];
        $otherSerializer['value'] = 'php';
        foreach ($otherSerializer['observations'] as &$observation) {
            $observation['value'] = 'php';
        }
        unset($observation);
        [, $otherSerializerEvaluation] = $this->evaluateInventory($otherSerializerInventory);
        $inactiveFacts = $this->factMap($inactiveEvaluation);
        $configurationFacts = $this->factMap($configurationEvaluation);
        $otherSerializerFacts = $this->factMap($otherSerializerEvaluation);
        $inactiveAssessment = $this->assessmentMap($inactiveEvaluation)['CVE-2026-115560'];

        self::assertSame('unknown', $inactiveFacts['advisory.CVE-2026-115560.worker-1.applicability']);
        self::assertSame('unknown', $configurationFacts['advisory.CVE-2026-115560.worker-1.applicability']);
        self::assertSame('unknown', $otherSerializerFacts['advisory.CVE-2026-115560.worker-1.applicability']);
        self::assertStringContainsString('per-directory overrides', $inactiveAssessment['rationale']);
    }

    public function test_cve_115560_does_not_combine_risk_settings_from_distinct_fpm_pools(): void
    {
        $inventory = $this->collectInventory('debian-fpm');
        $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled']['observations'][] = [
            'value' => '1',
            'file' => '/etc/php/8.2/fpm/pool.d/risky.conf',
            'context' => 'pool:risky',
            'configuration_root' => '/etc/php/8.2/fpm',
        ];
        $inventory['configuration_by_sapi']['fpm']['session.serialize_handler']['observations'][] = [
            'value' => 'php_binary',
            'file' => '/etc/php/8.2/fpm/pool.d/other.conf',
            'context' => 'pool:other',
            'configuration_root' => '/etc/php/8.2/fpm',
        ];

        [, $evaluation] = $this->evaluateInventory($inventory);
        $assessment = $this->assessmentMap($evaluation)['CVE-2026-115560'];

        self::assertSame('unknown', $assessment['verdict']);
        self::assertSame('unknown', $assessment['patch_status']);
    }

    public function test_cve_115560_does_not_combine_global_and_pool_settings_from_distinct_php_installs(): void
    {
        $inventory = $this->collectInventory('debian-fpm');
        $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled']['observations'][] = [
            'value' => '1',
            'file' => '/etc/php/8.3/fpm/php.ini',
            'context' => 'global',
            'configuration_root' => '/etc/php/8.3/fpm',
        ];
        $inventory['configuration_by_sapi']['fpm']['session.serialize_handler']['observations'][] = [
            'value' => 'php_binary',
            'file' => '/etc/php/8.2/fpm/pool.d/www.conf',
            'context' => 'pool:www',
            'configuration_root' => '/etc/php/8.2/fpm',
        ];

        [, $evaluation] = $this->evaluateInventory($inventory);
        $assessment = $this->assessmentMap($evaluation)['CVE-2026-115560'];

        self::assertSame('unknown', $assessment['verdict']);
        self::assertSame('unknown', $assessment['patch_status']);
    }

    public function test_cve_115560_does_not_combine_settings_when_configuration_root_is_unknown(): void
    {
        $inventory = $this->collectInventory('cve115560-config');
        foreach ($inventory['configuration_by_sapi']['fpm']['session.serialize_handler']['observations'] as &$observation) {
            $observation['configuration_root'] = null;
        }
        unset($observation);

        [, $evaluation] = $this->evaluateInventory($inventory);
        $assessment = $this->assessmentMap($evaluation)['CVE-2026-115560'];

        self::assertSame('unknown', $assessment['verdict']);
        self::assertSame('unknown', $assessment['patch_status']);
    }

    public function test_cli_only_settings_do_not_become_fpm_evidence(): void
    {
        [$inventory, $evaluation] = $this->evaluate('cli-only-config-fpm');
        $assessment = $this->assessmentMap($evaluation);

        self::assertSame('observed', $inventory['configuration_by_sapi']['cli']['session.upload_progress.enabled']['state']);
        self::assertSame('unknown', $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled']['state']);
        self::assertSame('unknown', $inventory['configuration_by_sapi']['fpm']['session.serialize_handler']['state']);
        self::assertSame('unknown', $assessment['CVE-2026-115560']['verdict']);
    }

    public function test_advisory_facts_carry_source_url_and_revision(): void
    {
        [, $evaluation] = $this->evaluate('debian-fpm');
        $sources = [];
        foreach ($evaluation['sources'] as $source) {
            $sources[$source['source_id']] = $source;
        }
        $mitigations = array_values(array_filter(
            $evaluation['facts'],
            static fn(array $fact): bool => str_contains($fact['key'], '.mitigation.'),
        ));

        self::assertNotEmpty($mitigations);
        foreach ($mitigations as $fact) {
            $value = $fact['value'];
            if (!is_array($value)
                || !is_string($value['as_of'] ?? null)
                || !is_string($value['source_url'] ?? null)
                || !is_string($value['revision'] ?? null)) {
                self::fail('Advisory mitigation facts include source metadata and an as-of revision.');
            }
            self::assertStringStartsWith('https://', $sources[$fact['source_id']]['locator']);
            self::assertSame('2026-10-25', $value['as_of']);
            self::assertStringStartsWith('https://', $value['source_url']);
            self::assertNotSame('', $value['revision']);
        }
    }

    public function test_synthetic_integrity_proof_is_required_for_the_fixed_package_verdict(): void
    {
        [$inventory, $evaluation] = $this->evaluate('synthetic-debian-integrity');
        self::assertTrue($inventory['workers'][0]['package_provenance']['verified']);
        $assessment = $this->assessmentMap($evaluation)['CVE-2026-109618'];
        self::assertSame('verified_fixed', $assessment['patch_status']);
        self::assertContains('fact.worker.1.package_provenance', $assessment['patch_evidence_ids']);
        self::assertContains('fact.advisory.catalog', $assessment['patch_evidence_ids']);
        $missingFactInventory = $inventory;
        $missingFactInventory['facts'] = array_values(array_filter(
            $inventory['facts'],
            static fn(array $fact): bool => $fact['key'] !== 'worker.1.package_provenance',
        ));
        [, $missingFact] = $this->evaluateInventory($missingFactInventory);
        self::assertSame('unknown', $this->assessmentMap($missingFact)['CVE-2026-109618']['patch_status']);
        $inventory['workers'][0]['package_provenance']['package_version'] = '8.2.34-1~deb12u1';
        [, $mismatched] = $this->evaluateInventory($inventory);
        self::assertSame('unknown', $this->assessmentMap($mismatched)['CVE-2026-109618']['patch_status']);
    }

    public function test_remote_citations_do_not_claim_catalog_bytes_were_captured_from_the_network(): void
    {
        [, $evaluation] = $this->evaluate('debian-fpm');
        $localCatalogSeen = false;
        foreach ($evaluation['sources'] as $source) {
            if ($source['kind'] === 'vendor_advisory') {
                self::assertStringStartsWith('https://', $source['locator']);
                self::assertNull($source['captured_digest']);
                self::assertSame('unknown', $source['freshness']);
                continue;
            }
            $localCatalogSeen = true;
            self::assertSame('source.advisory-catalog', $source['source_id']);
            self::assertSame(AdvisoryCatalog::load()->digest, $source['captured_digest']);
            self::assertStringStartsWith('php-runtime-audit:advisory-catalog:', $source['locator']);
        }
        self::assertTrue($localCatalogSeen);
        self::assertSame('advisory.catalog', $evaluation['facts'][0]['key']);
        self::assertSame('source.advisory-catalog', $evaluation['facts'][0]['source_id']);
    }

    /**
     * @phpstan-return array{RuntimeInventory, AdvisoryEvaluation}
     */
    private function evaluate(string $name): array
    {
        $inventory = $this->collectInventory($name);

        return $this->evaluateInventory($inventory);
    }

    /** @phpstan-return RuntimeInventory */
    private function collectInventory(string $name): array
    {
        $fixtureRoot = dirname(__DIR__) . '/fixtures/runtime/' . $name;
        $root = $fixtureRoot;
        $temporaryRoot = null;
        if ($name === 'synthetic-debian-integrity') {
            $temporaryRoot = sys_get_temp_dir() . '/pra-advisory-integrity-' . bin2hex(random_bytes(8));
            $this->copyDirectory($fixtureRoot, $temporaryRoot);
            unlink($temporaryRoot . '/proc/123/exe');
            self::assertTrue(symlink('../../usr/sbin/php-fpm8.2', $temporaryRoot . '/proc/123/exe'));
            $root = $temporaryRoot;
        }

        try {
            return (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-25T00:00:00Z',
            ))->collect();
        } finally {
            if ($temporaryRoot !== null) {
                $this->removeDirectory($temporaryRoot);
            }
        }
    }

    private function copyDirectory(string $source, string $destination): void
    {
        mkdir($destination, 0777, true);
        foreach (new \DirectoryIterator($source) as $entry) {
            if ($entry->isDot()) {
                continue;
            }
            $target = $destination . '/' . $entry->getFilename();
            if ($entry->isDir()) {
                $this->copyDirectory($entry->getPathname(), $target);
            } else {
                copy($entry->getPathname(), $target);
            }
        }
    }

    private function removeDirectory(string $directory): void
    {
        foreach (new \DirectoryIterator($directory) as $entry) {
            if ($entry->isDot()) {
                continue;
            }
            if ($entry->isDir()) {
                $this->removeDirectory($entry->getPathname());
            } else {
                unlink($entry->getPathname());
            }
        }
        rmdir($directory);
    }

    /** @param RuntimeInventory $inventory
     * @phpstan-return array{RuntimeInventory, AdvisoryEvaluation}
     */
    private function evaluateInventory(array $inventory): array
    {
        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());

        return [$inventory, $evaluation];
    }

    /**
     * @phpstan-param AdvisoryEvaluation $evaluation
     * @phpstan-return array<string, AdvisoryAssessment>
     */
    private function assessmentMap(array $evaluation): array
    {
        $result = [];
        foreach ($evaluation['assessments'] as $assessment) {
            $recordParts = explode(':', $assessment['record_id']);
            $subjectId = $assessment['subject_id'];
            $rank = str_starts_with($subjectId, 'worker-') || str_starts_with($subjectId, 'apache-')
                ? 3
                : (str_starts_with($subjectId, 'cli-') ? 2 : (str_starts_with($subjectId, 'package-') ? 1 : 0));
            $current = $result[$recordParts[1]] ?? null;
            $currentSubjectId = is_array($current) ? $current['subject_id'] : '';
            $currentRank = str_starts_with($currentSubjectId, 'worker-') || str_starts_with($currentSubjectId, 'apache-')
                ? 3
                : (str_starts_with($currentSubjectId, 'cli-') ? 2 : (str_starts_with($currentSubjectId, 'package-') ? 1 : -1));
            if ($rank > $currentRank) {
                $result[$recordParts[1]] = $assessment;
            }
        }

        return $result;
    }

    /** @phpstan-param AdvisoryEvaluation $evaluation
     * @return array<string, mixed>
     */
    private function factMap(array $evaluation): array
    {
        $result = [];
        foreach ($evaluation['facts'] as $fact) {
            $result[$fact['key']] = $fact['value'];
        }

        return $result;
    }
}
