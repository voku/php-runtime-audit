<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\Advisories;

use PHPUnit\Framework\TestCase;
use voku\PhpRuntimeAudit\Advisories\AdvisoryCatalog;
use voku\PhpRuntimeAudit\Advisories\AdvisoryEvaluator;
use voku\PhpRuntimeAudit\Advisories\RuntimeAuditReportBuilder;
use voku\PhpRuntimeAudit\Evidence\EvidenceValidator;
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
        // 4 runtime targets x 19 bundled advisories.
        self::assertSame(76, $report['summary']['assessment_count']);
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

    public function test_cli_target_evidence_cites_its_own_runtime_fact_not_a_neighboring_one(): void
    {
        [$inventory, $evaluation] = $this->evaluate('debian-fpm');
        $cliRuntime = $inventory['runtimes'][0];
        self::assertSame('cli', $cliRuntime['kind']);

        $ownVersionFact = null;
        foreach ($inventory['facts'] as $fact) {
            if ($fact['key'] === 'runtime.cli.1.version') {
                $ownVersionFact = $fact;
            }
        }
        self::assertNotNull($ownVersionFact, 'The collector must record a runtime.cli.1.version fact for the single discovered CLI runtime.');
        self::assertSame($cliRuntime['version'], $ownVersionFact['value']);

        $basisFact = null;
        foreach ($evaluation['facts'] as $fact) {
            if (str_starts_with($fact['key'], 'advisory.')
                && str_ends_with($fact['key'], '.' . $cliRuntime['id'] . '.assessment_basis')) {
                $basisFact = $fact;
                break;
            }
        }
        self::assertNotNull($basisFact, 'The CLI target must have an assessment_basis fact.');
        self::assertIsArray($basisFact['value']);
        self::assertSame(
            $ownVersionFact['fact_id'],
            $basisFact['value']['runtime_fact_id'],
            'A CLI target must cite its own runtime.cli.N.version fact as evidence, not a neighboring runtime index.',
        );
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

    public function test_unversioned_apache_module_resolves_package_identity_via_dpkg_provenance_without_claiming_a_fix(): void
    {
        [$inventory, $evaluation] = $this->evaluate('synthetic-debian-apache-integrity');
        $worker = $inventory['workers'][0];
        self::assertSame('apache', $worker['kind']);
        self::assertSame(['/usr/lib/apache2/modules/libphp.so'], $worker['apache_php_modules']);
        self::assertTrue($worker['package_provenance']['verified']);

        $assessment = $this->assessmentMap($evaluation);

        // The filename alone cannot identify the module's package or version, so no patch
        // status is ever claimed from it; only the evidence cited in the rationale improves.
        self::assertSame('unknown', $assessment['CVE-2026-109618']['patch_status']);
        self::assertStringContainsString('Package: libapache2-mod-php8.2 8.2.35-1~deb12u1.', $assessment['CVE-2026-109618']['rationale']);
    }

    public function test_fpm_branches_falls_back_to_verified_provenance_for_an_unversioned_apache_module(): void
    {
        $inventory = $this->collectInventory('synthetic-debian-apache-integrity');
        self::assertTrue($inventory['workers'][0]['package_provenance']['verified']);

        $method = new \ReflectionMethod(AdvisoryEvaluator::class, 'fpmBranches');
        $method->setAccessible(true);
        self::assertSame(['8.2'], $method->invoke(new AdvisoryEvaluator(), $inventory));
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

    public function test_cve_115560_distinct_fpm_pools_are_correlated_by_shared_store_not_merged(): void
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

        // Distinct pools are still never merged into one same-context writer. They are, however,
        // pools of one install with no save_path, so they may share its default session store
        // (the advisory: separate pools do not imply separate storage). That shared-store
        // correlation, not a merged context, is what raises the investigation.
        self::assertSame('needs_investigation', $assessment['verdict']);
        self::assertSame('unknown', $assessment['patch_status']);
        self::assertStringContainsString('appear to share one default session location', $assessment['rationale']);
        self::assertStringNotContainsString('contain upload progress enabled and a serialization handler named', $assessment['rationale']);
    }

    public function test_cve_115560_distinct_debian_installs_correlate_only_through_the_shared_default_store(): void
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

        // Settings of distinct installs are never merged into one same-context writer. Both roots
        // are Debian packages, though, which share /var/lib/php/sessions by default, so the
        // shared-store correlation (8.3 enables upload progress with php, 8.2 reads with
        // php_binary) raises the investigation.
        self::assertSame('needs_investigation', $assessment['verdict']);
        self::assertSame('unknown', $assessment['patch_status']);
        self::assertStringContainsString('appear to share one default session location', $assessment['rationale']);
        self::assertStringNotContainsString('contain upload progress enabled and a serialization handler named', $assessment['rationale']);
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
            self::assertSame('2026-11-19', $value['as_of']);
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

    public function test_cve_115560_patch_axis_uses_vendor_provenance_independently_of_configuration(): void
    {
        $catalog = $this->catalogWithSyntheticNovemberDebianRules();
        $inventory = $this->collectInventory('synthetic-debian-integrity');

        // Verified fix but unobserved session configuration: never a no-action verdict.
        $unobservedInventory = $inventory;
        foreach (['session.upload_progress.enabled', 'session.serialize_handler'] as $setting) {
            $unobservedInventory['configuration_by_sapi']['fpm'][$setting] = ['value' => null, 'state' => 'unknown', 'files' => [], 'observations' => []];
        }
        [, $unobservedEvaluation] = $this->evaluateInventory($unobservedInventory, $catalog);
        $unobserved = $this->assessmentMap($unobservedEvaluation)['CVE-2026-115560'];
        $unobservedExposure = $this->factMap($unobservedEvaluation)['advisory.CVE-2026-115560.worker-1.configuration_exposure'];
        self::assertIsArray($unobservedExposure);
        self::assertSame('unknown', $unobservedExposure['state']);
        self::assertSame('needs_investigation', $unobserved['verdict']);
        self::assertSame('verified_fixed', $unobserved['patch_status']);
        self::assertSame(['patch_status', 'compromise_evidence'], $unobservedExposure['independent_of']);

        // Verified fix, upload progress enabled with a non-advisory serializer: other store writers
        // are not collected, so this is still not a no-action result.
        [, $enabledEvaluation] = $this->evaluateInventory($this->withFpmSessionSettings($inventory, 'On', 'php'), $catalog);
        $enabled = $this->assessmentMap($enabledEvaluation)['CVE-2026-115560'];
        $enabledExposure = $this->factMap($enabledEvaluation)['advisory.CVE-2026-115560.worker-1.configuration_exposure'];
        self::assertIsArray($enabledExposure);
        self::assertSame('unknown', $enabledExposure['state']);
        self::assertSame('needs_investigation', $enabled['verdict']);
        self::assertSame('verified_fixed', $enabled['patch_status']);
        self::assertStringContainsString('cross-store serializer mismatch', $enabled['rationale']);

        // Verified fix and upload progress observed disabled in the collected configuration.
        [, $cleanEvaluation] = $this->evaluateInventory($this->withFpmSessionSettings($inventory, '0', 'php'), $catalog);
        $clean = $this->assessmentMap($cleanEvaluation)['CVE-2026-115560'];
        $cleanExposure = $this->factMap($cleanEvaluation)['advisory.CVE-2026-115560.worker-1.configuration_exposure'];
        // Locally disabled upload progress is not store-wide proof, so it is still not a no-action
        // verdict; the patch axis stays verified_fixed with its evidence.
        self::assertSame('verified_fixed', $clean['patch_status']);
        self::assertSame('needs_investigation', $clean['verdict']);
        self::assertSame('unknown', $clean['compromise_evidence']['status']);
        self::assertContains('fact.worker.1.package_provenance', $clean['patch_evidence_ids']);
        self::assertStringContainsString('other store writers are not collected', $clean['rationale']);
        self::assertIsArray($cleanExposure);
        self::assertSame('not_observed', $cleanExposure['state']);

        $risky = $this->withFpmSessionSettings($inventory, '1', 'php_serialize');
        [, $riskyEvaluation] = $this->evaluateInventory($risky, $catalog);
        $assessment = $this->assessmentMap($riskyEvaluation)['CVE-2026-115560'];
        $exposure = $this->factMap($riskyEvaluation)['advisory.CVE-2026-115560.worker-1.configuration_exposure'];

        self::assertSame('needs_investigation', $assessment['verdict']);
        self::assertSame('verified_fixed', $assessment['patch_status']);
        self::assertNotSame([], $assessment['patch_evidence_ids']);
        self::assertNotContains('fact.advisory.CVE-2026-115560.worker-1.configuration_exposure', $assessment['patch_evidence_ids']);
        self::assertSame('unknown', $assessment['compromise_evidence']['status']);
        self::assertStringContainsString('does not make an explicitly enabled upload-progress path safe', $assessment['rationale']);
        self::assertIsArray($exposure);
        self::assertSame('needs_investigation', $exposure['state']);
        self::assertIsArray($exposure['derived_from_fact_ids']);
        self::assertNotSame([], $exposure['derived_from_fact_ids']);
    }

    public function test_cve_115560_risky_configuration_on_an_unpatched_runtime_keeps_both_axes(): void
    {
        $catalog = $this->catalogWithSyntheticNovemberDebianRules('8.2.36-1~deb12u1');
        $inventory = $this->withFpmSessionSettings($this->collectInventory('synthetic-debian-integrity'), 'On', 'php_binary');

        [, $evaluation] = $this->evaluateInventory($inventory, $catalog);
        $assessment = $this->assessmentMap($evaluation)['CVE-2026-115560'];
        $exposure = $this->factMap($evaluation)['advisory.CVE-2026-115560.worker-1.configuration_exposure'];

        // The upgrade action must survive; the configuration finding stays on its own axis.
        self::assertSame('potentially_affected', $assessment['verdict']);
        self::assertSame('potentially_affected', $assessment['patch_status']);
        self::assertNotSame([], $assessment['patch_evidence_ids']);
        self::assertStringContainsString('also needs investigation', $assessment['rationale']);
        self::assertIsArray($exposure);
        self::assertSame('needs_investigation', $exposure['state']);
    }

    public function test_schema_and_remediation_accept_needs_investigation_with_verified_fixed_patch(): void
    {
        $catalog = $this->catalogWithSyntheticNovemberDebianRules();
        $inventory = $this->withFpmSessionSettings($this->collectInventory('synthetic-debian-integrity'), '1', 'php_serialize');
        [, $evaluation] = $this->evaluateInventory($inventory, $catalog);

        /** @var RuntimeAuditReport $report */
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);
        $records = array_values(array_filter(
            $report['records'],
            static fn(array $record): bool => ($record['record_type'] ?? null) === 'assessment'
                && is_string($record['record_id'] ?? null)
                && str_contains($record['record_id'], 'CVE-2026-115560:worker-'),
        ));
        self::assertCount(1, $records);
        self::assertSame('needs_investigation', $records[0]['verdict']);
        self::assertSame('verified_fixed', $records[0]['patch_status']);
    }

    public function test_cve_115560_disabled_upload_progress_is_not_a_patch_claim(): void
    {
        $inventory = $this->withFpmSessionSettings($this->collectInventory('synthetic-debian-integrity'), '0', 'php_serialize');

        [, $evaluation] = $this->evaluateInventory($inventory);
        $assessment = $this->assessmentMap($evaluation)['CVE-2026-115560'];
        $exposure = $this->factMap($evaluation)['advisory.CVE-2026-115560.worker-1.configuration_exposure'];

        self::assertSame('unknown', $assessment['verdict']);
        self::assertSame('unknown', $assessment['patch_status']);
        self::assertSame([], $assessment['patch_evidence_ids']);
        self::assertSame('unknown', $assessment['compromise_evidence']['status']);
        self::assertIsArray($exposure);
        self::assertSame('not_observed', $exposure['state']);
    }

    public function test_cve_126714_upload_progress_disabled_does_not_remove_unpatched_exposure(): void
    {
        $catalog = $this->catalogWithSyntheticNovemberDebianRules('8.2.36-1~deb12u1');
        $inventory = $this->withFpmSessionSettings($this->collectInventory('synthetic-debian-integrity'), '0', 'php');

        [, $evaluation] = $this->evaluateInventory($inventory, $catalog);
        $assessment = $this->assessmentMap($evaluation)['CVE-2026-126714'];
        $exposure = $this->factMap($evaluation)['advisory.CVE-2026-126714.worker-1.configuration_exposure'];

        self::assertSame('potentially_affected', $assessment['verdict']);
        self::assertSame('potentially_affected', $assessment['patch_status']);
        self::assertSame('unknown', $assessment['compromise_evidence']['status']);
        self::assertIsArray($exposure);
        self::assertSame('unknown', $exposure['state']);
        self::assertIsString($exposure['reason']);
        self::assertStringContainsString('session.save_handler', $exposure['reason']);
        self::assertSame(['fact.configuration.fpm.session.save_handler'], $exposure['derived_from_fact_ids']);
    }

    public function test_cve_126714_without_vendor_rule_stays_unknown_despite_upstream_threshold(): void
    {
        [, $evaluation] = $this->evaluate('synthetic-debian-integrity');
        $assessment = $this->assessmentMap($evaluation)['CVE-2026-126714'];

        self::assertSame('unknown', $assessment['verdict']);
        self::assertSame('unknown', $assessment['patch_status']);
        self::assertSame([], $assessment['patch_evidence_ids']);
    }

    public function test_bundled_catalog_assesses_every_target_without_a_budget_gap(): void
    {
        [$inventory, $evaluation] = $this->evaluate('debian-fpm');
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);

        self::assertArrayNotHasKey('omitted_subject_ids', $evaluation);
        foreach ($report['records'] as $record) {
            foreach (is_array($record['entries'] ?? null) ? $record['entries'] : [] as $entry) {
                self::assertIsArray($entry);
                self::assertNotSame('advisory.assessment-budget', $entry['check_id'] ?? null);
            }
        }
    }

    public function test_large_catalog_on_a_multi_version_host_reports_omitted_subjects_instead_of_failing(): void
    {
        $catalog = self::syntheticCatalogWithAdvisoryCount(19);
        $inventory = $this->withExtraPhpPackages($this->collectInventory('debian-fpm'), 12);

        [, $evaluation] = $this->evaluateInventory($inventory, $catalog);
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);

        // 256 / 19 advisories = 13 targets assessed; the 16-target host loses 3, packages first.
        self::assertSame(13 * 19, $report['summary']['assessment_count']);
        self::assertLessThanOrEqual(AdvisoryEvaluator::MAX_ASSESSMENTS, $report['summary']['assessment_count']);
        $omitted = $evaluation['omitted_subject_ids'] ?? [];
        self::assertCount(3, $omitted);
        self::assertSame(3, $report['summary']['omitted_subject_count']);
        foreach ($omitted as $subjectId) {
            self::assertStringStartsWith('package-', $subjectId);
        }
        $assessedSubjects = array_unique(array_column($evaluation['assessments'], 'subject_id'));
        self::assertNotSame([], array_filter($assessedSubjects, static fn(string $id): bool => str_starts_with($id, 'worker-')));
        self::assertNotSame([], array_filter($assessedSubjects, static fn(string $id): bool => str_starts_with($id, 'cli-')));
        self::assertSame([], array_intersect($assessedSubjects, $omitted));

        $budgetEntry = null;
        foreach ($report['records'] as $record) {
            foreach (is_array($record['entries'] ?? null) ? $record['entries'] : [] as $entry) {
                if (is_array($entry) && ($entry['check_id'] ?? null) === 'advisory.assessment-budget') {
                    $budgetEntry = $entry;
                }
            }
        }
        self::assertIsArray($budgetEntry);
        self::assertSame('blocked', $budgetEntry['status']);
        self::assertIsString($budgetEntry['gap']);
        self::assertStringContainsString('3 runtime subject(s) were not assessed', $budgetEntry['gap']);
        self::assertStringContainsString('further identical workers', $budgetEntry['gap']);
        self::assertStringContainsString($omitted[0], $budgetEntry['gap']);
    }

    public function test_fact_budget_keeps_a_host_with_many_php_packages_reportable(): void
    {
        $catalog = self::syntheticCatalogWithAdvisoryCount(19);
        $inventory = $this->withExtraPhpPackages($this->collectInventory('debian-fpm'), 400);

        [, $evaluation] = $this->evaluateInventory($inventory, $catalog);
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);

        $observationFacts = 0;
        foreach ($report['records'] as $record) {
            if (($record['record_type'] ?? null) === 'observation' && is_array($record['facts'] ?? null)) {
                $observationFacts += count($record['facts']);
            }
        }
        self::assertLessThanOrEqual(AdvisoryEvaluator::MAX_REPORT_FACTS, $observationFacts);
        self::assertGreaterThan(0, $report['summary']['omitted_subject_count']);
        self::assertSame(count($evaluation['omitted_subject_ids'] ?? []), $report['summary']['omitted_subject_count']);
        // The running web worker is always among the assessed subjects.
        self::assertNotSame([], array_filter(
            array_column($evaluation['assessments'], 'subject_id'),
            static fn(string $id): bool => str_starts_with($id, 'worker-'),
        ));
    }

    public function test_identical_pool_children_do_not_push_out_the_cli_or_packages(): void
    {
        $catalog = self::syntheticCatalogWithAdvisoryCount(19);
        $inventory = $this->collectInventory('debian-fpm');
        $master = $inventory['workers'][0];
        for ($child = 1; $child <= 15; ++$child) {
            $copy = $master;
            $copy['id'] = 'worker-' . (500 + $child) . '-1';
            $copy['pid'] = 500 + $child;
            $inventory['workers'][] = $copy;
        }

        [, $evaluation] = $this->evaluateInventory($inventory, $catalog);
        $assessed = array_values(array_unique(array_column($evaluation['assessments'], 'subject_id')));

        self::assertContains($master['id'], $assessed);
        self::assertNotSame([], array_filter($assessed, static fn(string $id): bool => str_starts_with($id, 'cli-')));
        self::assertNotSame([], array_filter($assessed, static fn(string $id): bool => str_starts_with($id, 'package-')));
        $omitted = $evaluation['omitted_subject_ids'] ?? [];
        self::assertNotSame([], $omitted);
        foreach ($omitted as $subjectId) {
            self::assertMatchesRegularExpression('/\Aworker-5[0-9]{2}-1\z/', $subjectId);
        }
    }

    public function test_a_worker_on_a_deleted_module_is_never_ranked_as_an_identical_child(): void
    {
        $catalog = self::syntheticCatalogWithAdvisoryCount(19);
        $inventory = $this->collectInventory('ubuntu-apache');
        $template = $inventory['workers'][0];
        self::assertSame('apache', $template['kind']);
        for ($child = 1; $child <= 14; ++$child) {
            $copy = $template;
            $copy['pid'] = 700 + $child;
            $copy['id'] = 'apache-' . (700 + $child);
            $copy['process_start_ticks_since_boot'] = 1;
            $inventory['workers'][] = $copy;
        }
        $stale = $template;
        $stale['pid'] = 799;
        $stale['id'] = 'apache-799';
        $stale['process_start_ticks_since_boot'] = 1;
        $stale['apache_php_module_deleted'] = true;
        $inventory['workers'][] = $stale;

        [, $evaluation] = $this->evaluateInventory($inventory, $catalog);
        $assessed = array_values(array_unique(array_column($evaluation['assessments'], 'subject_id')));

        self::assertNotSame([], $evaluation['omitted_subject_ids'] ?? []);
        self::assertContains('apache-799-1-1', $assessed);
        self::assertNotContains('apache-799-1-1', $evaluation['omitted_subject_ids'] ?? []);
    }

    public function test_an_inventory_that_leaves_no_fact_room_reports_every_subject_as_omitted(): void
    {
        $catalog = AdvisoryCatalog::load();
        $catalogFacts = 1;
        foreach ($catalog->advisories as $advisory) {
            $catalogFacts += 2 + count($advisory['mitigations']);
        }
        $inventory = $this->collectInventory('debian-fpm');
        [, $unbudgeted] = $this->evaluateInventory($inventory, $catalog);
        $subjects = array_values(array_unique(array_column($unbudgeted['assessments'], 'subject_id')));
        // One fact short of the limit: no target fits (each needs at least two facts per advisory).
        $inventory = $this->withPaddingFacts($inventory, AdvisoryEvaluator::MAX_REPORT_FACTS - $catalogFacts - 1);

        [, $evaluation] = $this->evaluateInventory($inventory, $catalog);
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);

        self::assertSame([], $evaluation['assessments']);
        self::assertSame(0, $report['summary']['assessment_count']);
        self::assertSame($subjects, $evaluation['omitted_subject_ids'] ?? []);
        self::assertSame(count($subjects), $report['summary']['omitted_subject_count']);
        self::assertSame(AdvisoryEvaluator::MAX_REPORT_FACTS - 1, $this->observationFactCount($report));
        self::assertSame('blocked', $this->budgetEntry($report)['status'] ?? null);
    }

    public function test_long_source_urls_cannot_push_the_report_over_its_byte_limit(): void
    {
        // 64 advisories x 4 targets pass the assessment and fact limits, but maximal titles,
        // source URLs and mitigation text in every assessment would push the report past 1 MiB.
        $catalog = $this->catalogFromTemplate(64, static function (int $index): array {
            $url = 'https://example.invalid/' . str_repeat('a', 226) . sprintf('/%05d', $index);
            self::assertSame(256, strlen($url));

            return [
                'title' => str_repeat('T', 256),
                'source_url' => $url,
                'mitigations' => [['setting' => str_repeat('s', 512), 'value' => str_repeat('v', 1024), 'effect' => 'partial', 'source_url' => $url]],
                'vendor_rules' => [],
            ];
        });
        $inventory = $this->collectInventory('debian-fpm');

        [, $evaluation] = $this->evaluateInventory($inventory, $catalog);
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);

        $json = json_encode($report, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        self::assertLessThanOrEqual(EvidenceValidator::MAX_INPUT_BYTES, strlen($json));
        self::assertNotSame([], $evaluation['omitted_subject_ids'] ?? []);
        self::assertGreaterThan(0, $report['summary']['assessment_count']);
        // The running web worker is admitted first.
        self::assertNotSame([], array_filter(
            array_column($evaluation['assessments'], 'subject_id'),
            static fn(string $id): bool => str_starts_with($id, 'worker-'),
        ));
    }

    public function test_vendor_rule_sources_that_would_exceed_the_source_limit_omit_targets_instead_of_failing(): void
    {
        $catalog = $this->catalogWithSyntheticNovemberDebianRules();
        $inventory = $this->collectInventory('debian-fpm');
        [, $catalogOnly] = $this->evaluateInventory($this->withPaddingSources($inventory, 0), $catalog);
        $vendorSource = 'https://example.invalid/synthetic-test-rule';
        self::assertContains($vendorSource, array_column($catalogOnly['sources'], 'locator'));
        $catalogSources = count($catalogOnly['sources']) - 1;
        $room = AdvisoryEvaluator::MAX_REPORT_SOURCES - count($inventory['sources']) - $catalogSources;

        // Exactly full without the vendor-rule source: the matching FPM worker cannot be admitted.
        $full = $this->withPaddingSources($inventory, $room);
        [, $evaluation] = $this->evaluateInventory($full, $catalog);
        $report = (new RuntimeAuditReportBuilder())->build($full, $evaluation);
        self::assertNotContains($vendorSource, array_column($evaluation['sources'], 'locator'));
        self::assertContains($catalogOnly['assessments'][0]['subject_id'], $evaluation['omitted_subject_ids'] ?? []);
        self::assertSame('blocked', $this->budgetEntry($report)['status'] ?? null);

        // One source of room more and the worker is assessed with its vendor-rule source.
        $fits = $this->withPaddingSources($inventory, $room - 1);
        [, $evaluation] = $this->evaluateInventory($fits, $catalog);
        (new RuntimeAuditReportBuilder())->build($fits, $evaluation);
        self::assertContains($vendorSource, array_column($evaluation['sources'], 'locator'));
        self::assertContains($catalogOnly['assessments'][0]['subject_id'], array_column($evaluation['assessments'], 'subject_id'));
    }

    public function test_a_catalog_at_the_source_url_cap_builds_a_report_within_the_source_limit(): void
    {
        // 32 advisories x (main + mitigation + matching vendor rule) = 96 distinct URLs, the cap.
        $catalog = $this->catalogFromTemplate(32, static fn(int $index): array => [
            'source_url' => 'https://example.invalid/advisory/' . $index,
            'mitigations' => [['setting' => 'x', 'value' => 'y', 'effect' => 'partial', 'source_url' => 'https://example.invalid/mitigation/' . $index]],
            'vendor_rules' => [[
                'vendor' => 'debian', 'release' => 'bookworm', 'package_names' => ['php8.2-fpm'],
                'fixed_version' => '8.2.35-1~deb12u1', 'source_url' => 'https://example.invalid/rule/' . $index, 'revision' => '2026-11-19',
            ]],
        ]);
        $inventory = $this->collectInventory('debian-fpm');

        [, $evaluation] = $this->evaluateInventory($inventory, $catalog);
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);

        $locators = array_column($evaluation['sources'], 'locator');
        self::assertContains('https://example.invalid/rule/0', $locators);
        $observationSources = 0;
        foreach ($report['records'] as $record) {
            if (($record['record_type'] ?? null) === 'observation' && is_array($record['sources'] ?? null)) {
                $observationSources += count($record['sources']);
            }
        }
        self::assertLessThanOrEqual(AdvisoryEvaluator::MAX_REPORT_SOURCES, $observationSources);
        self::assertGreaterThan(0, $report['summary']['assessment_count']);
    }

    public function test_identical_unpackaged_container_workers_do_not_push_out_the_cli(): void
    {
        $inventory = $this->collectInventory('container-fpm');
        $master = $inventory['workers'][0];
        self::assertSame('fpm', $master['kind']);
        self::assertIsString($master['executable_path']);
        for ($child = 1; $child <= 15; ++$child) {
            $copy = $master;
            $copy['id'] = 'worker-' . (500 + $child) . '-1';
            $copy['pid'] = 500 + $child;
            $inventory['workers'][] = $copy;
        }
        // Another FPM binary on the same host is a distinct runtime, not an identical child.
        $other = $master;
        $other['id'] = 'worker-600-1';
        $other['pid'] = 600;
        $other['executable_path'] = '/opt/other/sbin/php-fpm';
        $inventory['workers'][] = $other;

        [, $evaluation] = $this->evaluateInventory($inventory);
        $assessed = array_values(array_unique(array_column($evaluation['assessments'], 'subject_id')));
        $omitted = $evaluation['omitted_subject_ids'] ?? [];

        self::assertContains($master['id'], $assessed);
        self::assertContains('worker-600-1', $assessed);
        self::assertNotSame([], array_filter($assessed, static fn(string $id): bool => str_starts_with($id, 'cli-')));
        self::assertNotSame([], $omitted);
        foreach ($omitted as $subjectId) {
            self::assertMatchesRegularExpression('/\Aworker-5[0-9]{2}-1\z/', $subjectId);
        }
    }

    public function test_unpackaged_workers_on_a_deleted_binary_keep_their_rank(): void
    {
        $inventory = $this->collectInventory('container-fpm');
        $master = $inventory['workers'][0];
        for ($child = 1; $child <= 15; ++$child) {
            $copy = $master;
            $copy['id'] = 'worker-' . (500 + $child) . '-1';
            $copy['pid'] = 500 + $child;
            $inventory['workers'][] = $copy;
        }
        $stale = $master;
        $stale['id'] = 'worker-599-1';
        $stale['pid'] = 599;
        $stale['executable_deleted'] = true;
        $inventory['workers'][] = $stale;

        [, $evaluation] = $this->evaluateInventory($inventory);

        self::assertContains('worker-599-1', array_column($evaluation['assessments'], 'subject_id'));
        self::assertNotContains('worker-599-1', $evaluation['omitted_subject_ids'] ?? []);
    }

    /**
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-return RuntimeInventory
     */
    private function withPaddingFacts(array $inventory, int $total): array
    {
        $sourceId = $inventory['facts'][0]['source_id'];
        for ($index = count($inventory['facts']); $index < $total; ++$index) {
            $inventory['facts'][] = ['fact_id' => 'fact.padding.' . $index, 'key' => 'padding.' . $index, 'value' => $index, 'source_id' => $sourceId];
        }
        self::assertCount($total, $inventory['facts']);

        return $inventory;
    }

    /**
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-return RuntimeInventory
     */
    private function withPaddingSources(array $inventory, int $count): array
    {
        $template = $inventory['sources'][0];
        for ($index = 0; $index < $count; ++$index) {
            $source = $template;
            $source['source_id'] = 'source.padding-' . $index;
            $source['locator'] = 'padding:' . $index;
            $inventory['sources'][] = $source;
        }

        return $inventory;
    }

    /** @param array<string, mixed> $report */
    private function observationFactCount(array $report): int
    {
        $count = 0;
        foreach (is_array($report['records'] ?? null) ? $report['records'] : [] as $record) {
            if (is_array($record) && ($record['record_type'] ?? null) === 'observation' && is_array($record['facts'] ?? null)) {
                $count += count($record['facts']);
            }
        }

        return $count;
    }

    /**
     * @param array<string, mixed> $report
     * @return array<mixed>|null
     */
    private function budgetEntry(array $report): ?array
    {
        foreach (is_array($report['records'] ?? null) ? $report['records'] : [] as $record) {
            foreach (is_array($record) && is_array($record['entries'] ?? null) ? $record['entries'] : [] as $entry) {
                if (is_array($entry) && ($entry['check_id'] ?? null) === 'advisory.assessment-budget') {
                    return $entry;
                }
            }
        }

        return null;
    }

    /** @param callable(int): array<string, mixed> $overrides */
    private function catalogFromTemplate(int $count, callable $overrides): AdvisoryCatalog
    {
        $json = file_get_contents(AdvisoryCatalog::defaultPath());
        self::assertIsString($json);
        $data = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
        self::assertIsArray($data);
        self::assertIsArray($data['advisories']);
        $template = $data['advisories'][0];
        self::assertIsArray($template);
        $data['advisories'] = [];
        for ($index = 0; $index < $count; ++$index) {
            $data['advisories'][] = array_merge($template, ['cve' => sprintf('CVE-2026-9%05d', $index)], $overrides($index));
        }
        $path = sys_get_temp_dir() . '/pra-budget-catalog-' . bin2hex(random_bytes(8)) . '.json';
        file_put_contents($path, json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
        try {
            return AdvisoryCatalog::load($path);
        } finally {
            unlink($path);
        }
    }

    public static function syntheticCatalogWithAdvisoryCount(int $count): AdvisoryCatalog
    {
        $json = file_get_contents(AdvisoryCatalog::defaultPath());
        self::assertIsString($json);
        $data = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
        self::assertIsArray($data);
        self::assertIsArray($data['advisories']);
        $template = $data['advisories'][0];
        for ($index = count($data['advisories']); $index < $count; ++$index) {
            $copy = $template;
            self::assertIsArray($copy);
            $copy['cve'] = sprintf('CVE-2026-9%05d', $index);
            $data['advisories'][] = $copy;
        }
        $path = sys_get_temp_dir() . '/pra-budget-catalog-' . bin2hex(random_bytes(8)) . '.json';
        file_put_contents($path, json_encode($data, JSON_THROW_ON_ERROR));
        try {
            return AdvisoryCatalog::load($path);
        } finally {
            unlink($path);
        }
    }

    /**
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-return RuntimeInventory
     */
    private function withExtraPhpPackages(array $inventory, int $count): array
    {
        $sourceId = $inventory['facts'][0]['source_id'];
        for ($added = 0; $added < $count; ++$added) {
            $index = count($inventory['packages']);
            $version = sprintf('8.%d.%d-1', 3 + intdiv($added, 4), $added);
            $inventory['packages'][] = ['name' => sprintf('php8.%d-%s', 3 + intdiv($added, 4), ['cli', 'fpm', 'cgi', 'cli'][$added % 4]), 'version' => $version];
            $inventory['facts'][] = ['fact_id' => 'fact.package.' . $index . '.version', 'key' => 'package.' . $index . '.version', 'value' => $version, 'source_id' => $sourceId];
        }

        return $inventory;
    }

    /**
     * Synthetic vendor rules for tests only; the bundled catalog carries no November vendor rules.
     */
    private function catalogWithSyntheticNovemberDebianRules(string $fixedVersion = '8.2.35-1~deb12u1'): AdvisoryCatalog
    {
        $json = file_get_contents(AdvisoryCatalog::defaultPath());
        self::assertIsString($json);
        $data = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
        self::assertIsArray($data);
        self::assertIsArray($data['advisories']);
        foreach ($data['advisories'] as &$advisory) {
            self::assertIsArray($advisory);
            if (!in_array($advisory['cve'], ['CVE-2026-115560', 'CVE-2026-126714'], true)) {
                continue;
            }
            $advisory['vendor_rules'] = [[
                'vendor' => 'debian',
                'release' => 'bookworm',
                'package_names' => ['php8.2-fpm'],
                'fixed_version' => $fixedVersion,
                'source_url' => 'https://example.invalid/synthetic-test-rule',
                'revision' => '2026-11-19',
            ]];
        }
        unset($advisory);
        $path = sys_get_temp_dir() . '/pra-advisory-catalog-' . bin2hex(random_bytes(8)) . '.json';
        file_put_contents($path, json_encode($data, JSON_THROW_ON_ERROR));
        try {
            return AdvisoryCatalog::load($path);
        } finally {
            unlink($path);
        }
    }

    /**
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-return RuntimeInventory
     */
    private function withFpmSessionSettings(array $inventory, string $uploadProgress, string $serializer): array
    {
        foreach (['session.upload_progress.enabled' => $uploadProgress, 'session.serialize_handler' => $serializer] as $setting => $value) {
            $inventory['configuration_by_sapi']['fpm'][$setting] = [
                'value' => $value,
                'state' => 'observed',
                'files' => ['/etc/php/8.2/fpm/php.ini'],
                'observations' => [[
                    'value' => $value,
                    'file' => '/etc/php/8.2/fpm/php.ini',
                    'context' => 'global',
                    'configuration_root' => '/etc/php/8.2/fpm',
                ]],
            ];
        }

        return $inventory;
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
    private function evaluateInventory(array $inventory, ?AdvisoryCatalog $catalog = null): array
    {
        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, $catalog ?? AdvisoryCatalog::load());

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
