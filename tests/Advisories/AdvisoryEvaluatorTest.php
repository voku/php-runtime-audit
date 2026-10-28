<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\Advisories;

use PHPUnit\Framework\TestCase;
use voku\PhpRuntimeAudit\Advisories\AdvisoryCatalog;
use voku\PhpRuntimeAudit\Advisories\AdvisoryEvaluator;
use voku\PhpRuntimeAudit\Advisories\RuntimeAuditReportBuilder;
use voku\PhpRuntimeAudit\Remediation\RemediationPlanBuilder;
use voku\PhpRuntimeAudit\RuntimeInventory\DiscoveredPhpCommand;
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
        self::assertSame(15, $report['summary']['assessment_count']);
        self::assertSame(5, $report['summary']['coverage_count']);
        self::assertSame('unknown', $report['summary']['compromise_evidence']);
        self::assertSame('coverage', $report['records'][1]['record_type']);
    }

    public function test_cli_coverage_uses_one_evidence_fact_per_runtime(): void
    {
        $root = sys_get_temp_dir() . '/pra-many-cli-runtimes-' . bin2hex(random_bytes(6));
        mkdir($root . '/usr/bin', 0777, true);
        $commands = [];
        for ($index = 0; $index < 103; ++$index) {
            $binaryPath = '/usr/bin/php7.' . $index;
            file_put_contents($root . $binaryPath, 'fixture PHP executable');
            $command = DiscoveredPhpCommand::fromPath($binaryPath, 'cli');
            $commands[$command->id()] = [
                'exit_code' => 0,
                'stdout' => json_encode([
                    'version' => '7.' . $index . '.0',
                    'sapi' => 'cli',
                    'extensions' => [],
                ], JSON_THROW_ON_ERROR),
            ];
        }
        file_put_contents($root . '/commands.json', json_encode(['commands' => $commands], JSON_THROW_ON_ERROR));

        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-27T00:00:00Z',
                '/usr/bin',
            ))->collect();

            self::assertCount(103, $inventory['runtimes']);
            self::assertCount(103, $inventory['coverage'][0]['evidence_ids']);
            self::assertSame('attempted', $inventory['coverage'][0]['status']);

            [, $evaluation] = $this->evaluateInventory($inventory);
            /** @var RuntimeAuditReport $report */
            $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);
            self::assertGreaterThan(0, $report['summary']['assessment_count']);
            self::assertSame(515, $this->countReportFactsWithPrefix($report, 'runtime.cli.'));
        } finally {
            $this->removeDirectory($root);
        }
    }

    public function test_many_untrusted_path_candidates_keep_discovery_coverage_bounded(): void
    {
        $root = sys_get_temp_dir() . '/pra-many-path-candidates-' . bin2hex(random_bytes(6));
        $candidateDirectory = $root . '/opt/php/bin';
        mkdir($candidateDirectory, 0777, true);
        for ($index = 0; $index < 600; ++$index) {
            file_put_contents($candidateDirectory . '/php7.' . $index, 'untrusted fixture executable');
        }
        file_put_contents($root . '/commands.json', '{"commands":{}}');

        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-27T00:00:00Z',
                '/opt/php/bin',
            ))->collect();
            $candidateFacts = array_values(array_filter(
                $inventory['facts'],
                static fn(array $fact): bool => str_starts_with($fact['key'], 'runtime.discovery.path_candidate.'),
            ));

            self::assertCount(600, $candidateFacts);
            self::assertCount(6, $inventory['coverage'][4]['evidence_ids']);
            self::assertSame('blocked', $inventory['coverage'][4]['status']);

            [, $evaluation] = $this->evaluateInventory($inventory);
            /** @var RuntimeAuditReport $report */
            $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);
            self::assertGreaterThan(0, $report['summary']['coverage_count']);
            self::assertSame(600, $this->countReportFactsWithPrefix($report, 'runtime.discovery.path_candidate.'));
        } finally {
            $this->removeDirectory($root);
        }
    }

    public function test_inactive_fpm_executable_receives_an_independent_assessment(): void
    {
        $inventory = $this->collectInventory('debian-fpm');
        $executableId = $inventory['fpm_executables'][0]['id'];
        $inventory['workers'] = [];

        [, $evaluation] = $this->evaluateInventory($inventory);
        $assessmentsBySubject = [];
        foreach ($evaluation['assessments'] as $assessment) {
            $assessmentsBySubject[$assessment['subject_id']] = $assessment;
        }

        self::assertArrayHasKey($executableId, $assessmentsBySubject);
        self::assertSame($executableId, $assessmentsBySubject[$executableId]['subject_id']);
        self::assertSame('unknown', $assessmentsBySubject[$executableId]['patch_status']);
    }

    public function test_vendor_catalog_package_names_are_always_assessed_as_package_subjects(): void
    {
        $inventory = $this->collectInventory('rhel10-fpm');
        $packageSourceId = null;
        foreach ($inventory['facts'] as $fact) {
            if ($fact['key'] === 'package.0.version') {
                $packageSourceId = $fact['source_id'];
                break;
            }
        }
        self::assertIsString($packageSourceId);

        foreach ([
            ['name' => 'php-common', 'version' => '8.3.36-1.el10_2'],
            ['name' => 'php8.4', 'version' => '8.4.27-1.el10_2'],
            ['name' => 'php8.4-common', 'version' => '8.4.27-1.el10_2'],
        ] as $package) {
            $index = count($inventory['packages']);
            $inventory['packages'][] = $package;
            $inventory['facts'][] = [
                'fact_id' => 'fact.package.' . $index . '.version',
                'key' => 'package.' . $index . '.version',
                'value' => $package['version'],
                'source_id' => $packageSourceId,
            ];
        }

        [, $evaluation] = $this->evaluateInventory($inventory);
        $assessmentsBySubject = [];
        foreach ($evaluation['assessments'] as $assessment) {
            $assessmentsBySubject[$assessment['subject_id']] = $assessment;
        }

        foreach ([
            ['name' => 'php', 'version' => '8.3.36-1.el10_2'],
            ['name' => 'php-common', 'version' => '8.3.36-1.el10_2'],
            ['name' => 'php8.4', 'version' => '8.4.27-1.el10_2'],
            ['name' => 'php8.4-common', 'version' => '8.4.27-1.el10_2'],
        ] as $package) {
            $subjectId = 'package-' . substr(hash('sha256', $package['name'] . "\0" . $package['version']), 0, 20);
            self::assertArrayHasKey($subjectId, $assessmentsBySubject, $package['name'] . ' gets a package assessment subject.');
        }
    }

    public function test_cli_assessment_basis_uses_its_matching_runtime_version_fact(): void
    {
        $inventory = $this->collectInventory('debian-fpm');
        $firstRuntimeId = $inventory['runtimes'][0]['id'];
        $secondRuntimeId = $this->appendCliRuntime($inventory, '/usr/local/bin/php-secondary', '8.4.27', 2);

        [, $evaluation] = $this->evaluateInventory($inventory);
        $basisBySubject = [];
        foreach ($evaluation['facts'] as $fact) {
            $prefix = 'advisory.CVE-2026-109618.';
            if (!str_starts_with($fact['key'], $prefix) || !str_ends_with($fact['key'], '.assessment_basis')) {
                continue;
            }
            $subjectId = substr($fact['key'], strlen($prefix), -strlen('.assessment_basis'));
            $basisBySubject[$subjectId] = $fact['value'];
        }

        self::assertIsArray($basisBySubject[$firstRuntimeId]);
        self::assertIsArray($basisBySubject[$secondRuntimeId]);
        self::assertSame('fact.runtime.cli.1.version', $basisBySubject[$firstRuntimeId]['runtime_fact_id']);
        self::assertSame('fact.runtime.cli.2.version', $basisBySubject[$secondRuntimeId]['runtime_fact_id']);
    }

    public function test_unowned_local_cli_does_not_inherit_a_vendor_package_verdict(): void
    {
        $inventory = $this->collectInventory('rhel10-fpm');
        $packageSourceId = null;
        foreach ($inventory['facts'] as $fact) {
            if ($fact['key'] === 'package.0.version') {
                $packageSourceId = $fact['source_id'];
                break;
            }
        }
        self::assertIsString($packageSourceId);

        $packageIndex = count($inventory['packages']);
        $inventory['packages'][] = ['name' => 'php-cli', 'version' => '8.3.35-1.el10_1'];
        $inventory['facts'][] = [
            'fact_id' => 'fact.package.' . $packageIndex . '.version',
            'key' => 'package.' . $packageIndex . '.version',
            'value' => '8.3.35-1.el10_1',
            'source_id' => $packageSourceId,
        ];
        $localCliId = $this->appendCliRuntime($inventory, '/usr/local/bin/php', '8.3.35', count($inventory['runtimes']) + 1);

        [, $evaluation] = $this->evaluateInventory($inventory);
        $assessmentsBySubject = [];
        foreach ($evaluation['assessments'] as $assessment) {
            if (str_starts_with($assessment['record_id'], 'assessment:CVE-2026-109618:')) {
                $assessmentsBySubject[$assessment['subject_id']] = $assessment;
            }
        }
        $packageId = 'package-' . substr(hash('sha256', "php-cli\0" . '8.3.35-1.el10_1'), 0, 20);

        self::assertSame('unknown', $assessmentsBySubject[$localCliId]['patch_status']);
        self::assertSame('potentially_affected', $assessmentsBySubject[$packageId]['patch_status']);
    }

    public function test_unowned_standard_cli_and_inactive_fpm_executable_do_not_inherit_vendor_verdicts(): void
    {
        $inventory = $this->collectInventory('debian-fpm-vulnerable');
        $inventory['workers'] = [];
        $cliId = $this->appendCliRuntime($inventory, '/usr/bin/php8.2', '8.2.34', 2);
        $fpmExecutableId = $inventory['fpm_executables'][0]['id'];

        [, $evaluation] = $this->evaluateInventory($inventory);
        $assessmentsBySubject = [];
        foreach ($evaluation['assessments'] as $assessment) {
            if (str_starts_with($assessment['record_id'], 'assessment:CVE-2026-109618:')) {
                $assessmentsBySubject[$assessment['subject_id']] = $assessment;
            }
        }
        $cliPackageId = 'package-' . substr(hash('sha256', "php8.2-cli\0" . '8.2.34-1~deb12u1'), 0, 20);
        $fpmPackageId = 'package-' . substr(hash('sha256', "php8.2-fpm\0" . '8.2.34-1~deb12u1'), 0, 20);

        self::assertSame('unknown', $assessmentsBySubject[$cliId]['patch_status']);
        self::assertSame('unknown', $assessmentsBySubject[$fpmExecutableId]['patch_status']);
        self::assertSame('potentially_affected', $assessmentsBySubject[$cliPackageId]['patch_status']);
        self::assertSame('potentially_affected', $assessmentsBySubject[$fpmPackageId]['patch_status']);
    }

    public function test_report_accepts_129_assessments_within_runtime_target_limit(): void
    {
        $inventory = $this->collectInventory('debian-fpm');
        for ($runtimeIndex = 2; $runtimeIndex <= 39; ++$runtimeIndex) {
            $this->appendCliRuntime(
                $inventory,
                '/usr/local/bin/php-candidate-' . $runtimeIndex,
                '8.3.35',
                $runtimeIndex,
            );
        }

        [, $evaluation] = $this->evaluateInventory($inventory);
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);

        self::assertSame(129, $report['summary']['assessment_count']);
        self::assertLessThan(1_048_576, strlen(json_encode($report, JSON_THROW_ON_ERROR)));
    }

    public function test_report_chunks_large_evidence_and_reports_omitted_assessment_targets(): void
    {
        $catalogJson = file_get_contents(AdvisoryCatalog::defaultPath());
        self::assertIsString($catalogJson);
        $catalogData = json_decode($catalogJson, true, 32, JSON_THROW_ON_ERROR);
        self::assertIsArray($catalogData);
        self::assertIsArray($catalogData['advisories'] ?? null);
        $catalogData['advisories'] = array_slice($catalogData['advisories'], 0, 1);
        $catalogPath = sys_get_temp_dir() . '/pra-one-advisory-' . bin2hex(random_bytes(6)) . '.json';
        $catalogJson = json_encode($catalogData, JSON_THROW_ON_ERROR);
        file_put_contents($catalogPath, $catalogJson);

        try {
            $catalog = AdvisoryCatalog::load($catalogPath);
            $inventory = $this->collectInventory('debian-fpm');
            for ($runtimeIndex = 2; $runtimeIndex <= 251; ++$runtimeIndex) {
                $this->appendCliRuntime(
                    $inventory,
                    '/usr/local/bin/php-candidate-' . $runtimeIndex,
                    '8.3.35',
                    $runtimeIndex,
                );
            }

            [, $evaluation] = $this->evaluateInventory($inventory, $catalog);
            self::assertCount(1, $evaluation['coverage']);
            self::assertSame('blocked', $evaluation['coverage'][0]['status']);
            $selectionFacts = array_values(array_filter(
                $evaluation['facts'],
                static fn(array $fact): bool => $fact['key'] === 'advisory.assessment_targets.truncated',
            ));
            self::assertCount(1, $selectionFacts);
            self::assertSame([
                'limit' => 128,
                'observed' => 255,
                'included' => 128,
                'omitted' => 127,
            ], $selectionFacts[0]['value']);

            $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);
            $observationRecords = array_values(array_filter(
                $report['records'],
                static fn(array $record): bool => ($record['record_type'] ?? null) === 'observation',
            ));
            self::assertGreaterThan(1, count($observationRecords));
            $includedFactCount = 0;
            foreach ($observationRecords as $record) {
                self::assertIsArray($record['sources'] ?? null);
                self::assertIsArray($record['facts'] ?? null);
                /** @var list<array<string, mixed>> $sources */
                $sources = $record['sources'];
                /** @var list<array<string, mixed>> $facts */
                $facts = $record['facts'];
                self::assertLessThanOrEqual(256, count($sources));
                self::assertLessThanOrEqual(1024, count($facts));
                $includedFactCount += count($facts);
                $sourceIds = array_column($sources, 'source_id');
                foreach ($facts as $fact) {
                    self::assertContains($fact['source_id'], $sourceIds);
                }
            }
            self::assertSame(count($inventory['facts']) + count($evaluation['facts']), $includedFactCount);
            self::assertSame(128, $report['summary']['assessment_count']);
            self::assertSame(6, $report['summary']['coverage_count']);

            $coverageRecords = array_values(array_filter(
                $report['records'],
                static fn(array $record): bool => ($record['record_type'] ?? null) === 'coverage',
            ));
            self::assertCount(1, $coverageRecords);
            self::assertIsArray($coverageRecords[0]['entries'] ?? null);
            /** @var list<array<string, mixed>> $coverageEntries */
            $coverageEntries = $coverageRecords[0]['entries'];
            $targetCoverage = array_values(array_filter(
                $coverageEntries,
                static fn(array $entry): bool => $entry['check_id'] === 'advisory.assessment_targets',
            ));
            self::assertCount(1, $targetCoverage);
            self::assertSame('blocked', $targetCoverage[0]['status']);
            self::assertIsString($targetCoverage[0]['gap']);
            self::assertStringContainsString('omitted 127', $targetCoverage[0]['gap']);
            self::assertLessThan(1_048_576, strlen(json_encode($report, JSON_THROW_ON_ERROR)));
        } finally {
            if (is_file($catalogPath)) {
                unlink($catalogPath);
            }
        }
    }

    public function test_report_supports_the_catalog_and_runtime_assessment_limits_together(): void
    {
        $catalogJson = file_get_contents(AdvisoryCatalog::defaultPath());
        self::assertIsString($catalogJson);
        $catalogData = json_decode($catalogJson, true, 32, JSON_THROW_ON_ERROR);
        self::assertIsArray($catalogData);
        self::assertIsArray($catalogData['advisories'] ?? null);
        $template = $catalogData['advisories'][0] ?? null;
        self::assertIsArray($template);
        $catalogData['advisories'] = [];
        for ($index = 0; $index < 64; ++$index) {
            $advisory = $template;
            $advisory['cve'] = sprintf('CVE-2030-%04d', 1000 + $index);
            $catalogData['advisories'][] = $advisory;
        }
        $catalogPath = sys_get_temp_dir() . '/pra-max-advisory-catalog-' . bin2hex(random_bytes(6)) . '.json';
        file_put_contents($catalogPath, json_encode($catalogData, JSON_THROW_ON_ERROR));

        try {
            $catalog = AdvisoryCatalog::load($catalogPath);
            $inventory = $this->collectInventory('debian-fpm');
            for ($runtimeIndex = 2; $runtimeIndex <= 124; ++$runtimeIndex) {
                $this->appendCliRuntime(
                    $inventory,
                    '/usr/local/bin/php-candidate-' . $runtimeIndex,
                    '8.3.35',
                    $runtimeIndex,
                );
            }

            [, $evaluation] = $this->evaluateInventory($inventory, $catalog);
            self::assertCount(8192, $evaluation['assessments']);

            $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);
            self::assertSame(8192, $report['summary']['assessment_count']);
            self::assertLessThanOrEqual(64 * 1024 * 1024, strlen(json_encode($report, JSON_THROW_ON_ERROR)));
            $observedFactCount = 0;
            foreach ($report['records'] as $record) {
                if (($record['record_type'] ?? null) === 'observation' && is_array($record['facts'] ?? null)) {
                    $observedFactCount += count($record['facts']);
                }
            }
            self::assertGreaterThan(4096, $observedFactCount);

            $plan = (new RemediationPlanBuilder())->build($report);
            self::assertCount(8192, $plan->actions);
            self::assertNotEmpty($plan->actions[count($plan->actions) - 1]->evidenceIds);

            $reportJson = json_encode($report, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
            $jsonBytes = strlen($reportJson) - 1;
            self::assertGreaterThan(1_048_576, $jsonBytes);
            self::assertLessThanOrEqual(RuntimeAuditReportBuilder::MAX_REPORT_BYTES, $jsonBytes);
            $cliResult = $this->runCli(
                [PHP_BINARY, dirname(__DIR__, 2) . '/bin/php-runtime-audit-report'],
                $reportJson,
            );
            self::assertSame(0, $cliResult['exit'], $cliResult['stderr']);
            $cliPlan = json_decode($cliResult['stdout'], true, 512, JSON_THROW_ON_ERROR);
            self::assertIsArray($cliPlan);
            self::assertSame('remediation_plan', $cliPlan['record_type'] ?? null);
            $cliActions = $cliPlan['actions'] ?? null;
            self::assertIsArray($cliActions);
            self::assertCount(8192, $cliActions);
            $lastAction = $cliActions[8191] ?? null;
            self::assertIsArray($lastAction);
            $lastActionEvidence = $lastAction['evidence_ids'] ?? null;
            self::assertIsArray($lastActionEvidence);
            self::assertNotEmpty($lastActionEvidence);
        } finally {
            if (is_file($catalogPath)) {
                unlink($catalogPath);
            }
        }
    }

    public function test_cli_fixed_version_does_not_verify_unowned_running_fpm(): void
    {
        [, $evaluation] = $this->evaluate('debian-fpm-vulnerable');
        $assessment = $this->assessmentMap($evaluation);
        $fpmPackageId = 'package-' . substr(hash('sha256', "php8.2-fpm\0" . '8.2.34-1~deb12u1'), 0, 20);
        $fpmPackageAssessment = null;
        foreach ($evaluation['assessments'] as $candidateAssessment) {
            if ($candidateAssessment['subject_id'] === $fpmPackageId
                && str_starts_with($candidateAssessment['record_id'], 'assessment:CVE-2026-109618:')) {
                $fpmPackageAssessment = $candidateAssessment;
                break;
            }
        }

        self::assertSame('unknown', $assessment['CVE-2026-109618']['patch_status']);
        self::assertSame('unknown', $assessment['CVE-2026-109619']['patch_status']);
        self::assertStringContainsString('Runtime: 8.2.34.', $assessment['CVE-2026-109618']['rationale']);
        self::assertIsArray($fpmPackageAssessment);
        self::assertSame('potentially_affected', $fpmPackageAssessment['patch_status']);
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
        [$inventory, $evaluation] = $this->evaluate('rhel10-fpm-pool-override');
        $poolWorker = $this->fpmPoolWorker($inventory, 'www');
        $assessment = $this->assessmentForSubject($evaluation, 'CVE-2026-115560', $poolWorker['id']);

        self::assertIsArray($assessment);
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

    public function test_deleted_apache_module_state_is_bound_to_its_exact_module_subject(): void
    {
        $inventory = $this->collectInventoryWithMixedApacheModuleDeletion();
        $worker = $inventory['workers'][0];
        self::assertSame(
            ['/usr/lib/apache2/modules/libphp8.2.so', '/usr/lib/apache2/modules/libphp8.3.so'],
            $worker['apache_php_modules'],
        );
        self::assertSame(['/usr/lib/apache2/modules/libphp8.2.so'], $worker['apache_php_module_deleted_paths']);

        [, $evaluation] = $this->evaluateInventory($inventory);
        $assessmentsBySubject = [];
        foreach ($evaluation['assessments'] as $assessment) {
            if (str_starts_with($assessment['record_id'], 'assessment:CVE-2026-109618:apache-')) {
                $assessmentsBySubject[$assessment['subject_id']] = $assessment;
            }
        }

        $workerIdentity = 'apache-' . $worker['pid'] . '-' . ($worker['process_start_ticks_since_boot'] ?? 'unknown') . '-';
        self::assertStringContainsString('deleted executable', $assessmentsBySubject[$workerIdentity . '1']['rationale']);
        self::assertStringNotContainsString('deleted executable', $assessmentsBySubject[$workerIdentity . '2']['rationale']);
    }

    public function test_apache_risk_configuration_requests_investigation_without_claiming_a_fix(): void
    {
        [, $evaluation] = $this->evaluate('ubuntu-apache');
        $assessment = $this->assessmentMap($evaluation)['CVE-2026-115560'];

        self::assertSame('needs_investigation', $assessment['verdict']);
        self::assertSame('unknown', $assessment['patch_status']);
    }

    public function test_custom_apache_module_path_does_not_inherit_debian_configuration_root(): void
    {
        $inventory = $this->collectInventoryWithApacheModule('/opt/custom/libphp8.3.so');
        self::assertSame(['/opt/custom/libphp8.3.so'], $inventory['workers'][0]['apache_php_modules']);
        self::assertSame(
            'observed',
            $inventory['configuration_by_sapi']['apache2']['session.upload_progress.enabled']['state'],
        );

        [, $evaluation] = $this->evaluateInventory($inventory);
        $assessments = array_values(array_filter(
            $evaluation['assessments'],
            static fn(array $assessment): bool => str_starts_with(
                $assessment['record_id'],
                'assessment:CVE-2026-115560:apache-',
            ),
        ));

        self::assertCount(1, $assessments);
        self::assertSame('unknown', $assessments[0]['verdict']);
        self::assertSame('unknown', $assessments[0]['patch_status']);
    }

    public function test_unversioned_apache_module_without_verified_package_provenance_does_not_inherit_configuration(): void
    {
        $inventory = $this->collectInventoryWithApacheModule('/usr/lib/apache2/modules/libphp.so');
        self::assertFalse($inventory['workers'][0]['package_provenance']['verified']);

        [, $evaluation] = $this->evaluateInventory($inventory);
        $assessments = array_values(array_filter(
            $evaluation['assessments'],
            static fn(array $assessment): bool => str_starts_with(
                $assessment['record_id'],
                'assessment:CVE-2026-115560:apache-',
            ),
        ));

        self::assertCount(1, $assessments);
        self::assertSame('unknown', $assessments[0]['verdict']);
        self::assertSame('unknown', $assessments[0]['patch_status']);
    }

    public function test_non_debian_apache_module_layout_does_not_inherit_debian_configuration_root(): void
    {
        $modulePath = '/usr/lib/apache2/modules/libphp8.3.so';
        $inventory = $this->collectInventoryWithApacheModule($modulePath, 'alpine');
        self::assertSame('alpine', $inventory['distribution']);
        self::assertSame([$modulePath], $inventory['workers'][0]['apache_php_modules']);

        [, $evaluation] = $this->evaluateInventory($inventory);
        $assessments = array_values(array_filter(
            $evaluation['assessments'],
            static fn(array $assessment): bool => str_starts_with(
                $assessment['record_id'],
                'assessment:CVE-2026-115560:apache-',
            ),
        ));

        self::assertCount(1, $assessments);
        self::assertSame('unknown', $assessments[0]['verdict']);
        self::assertSame('unknown', $assessments[0]['patch_status']);
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
        self::assertSame('needs_investigation', $assessment['CVE-2026-115560']['verdict']);
        self::assertSame('unknown', $assessment['CVE-2026-115560']['patch_status']);
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
        [$suspiciousInventory, $suspiciousEvaluation] = $this->evaluate('cve115560-config');
        $suspiciousPoolWorker = $this->fpmPoolWorker($suspiciousInventory, 'www');
        [, $conflictingEvaluation] = $this->evaluate('configuration-conflict');
        $suspicious = $this->assessmentForSubject($suspiciousEvaluation, 'CVE-2026-115560', $suspiciousPoolWorker['id']);
        $conflicting = $this->assessmentMap($conflictingEvaluation)['CVE-2026-115560'];

        self::assertIsArray($suspicious);
        self::assertSame('needs_investigation', $suspicious['verdict']);
        self::assertSame('unknown', $suspicious['patch_status']);
        self::assertSame('needs_investigation', $conflicting['verdict']);
        self::assertSame('unknown', $conflicting['patch_status']);
        self::assertStringContainsString('precedence', $conflicting['rationale']);
    }

    public function test_cve_115560_keeps_positive_fpm_risk_when_unrelated_config_discovery_is_incomplete(): void
    {
        $fixtureRoot = dirname(__DIR__) . '/fixtures/runtime/cve115560-config';
        $temporaryRoot = sys_get_temp_dir() . '/pra-fpm-risk-incomplete-config-' . bin2hex(random_bytes(8));
        $this->copyDirectory($fixtureRoot, $temporaryRoot);
        self::assertTrue(symlink('/unavailable/configuration-root', $temporaryRoot . '/etc/php'));

        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($temporaryRoot),
                $temporaryRoot,
                '2026-10-27T00:00:00Z',
            ))->collect();
            $uploadSetting = $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled'];
            $serializeSetting = $inventory['configuration_by_sapi']['fpm']['session.serialize_handler'];
            self::assertSame('unknown', $uploadSetting['state']);
            self::assertSame('unknown', $serializeSetting['state']);
            self::assertNotEmpty($uploadSetting['observations']);
            self::assertNotEmpty($serializeSetting['observations']);

            $poolWorker = $this->fpmPoolWorker($inventory, 'www');
            [, $evaluation] = $this->evaluateInventory($inventory);
            $assessment = $this->assessmentForSubject($evaluation, 'CVE-2026-115560', $poolWorker['id']);

            self::assertIsArray($assessment);
            self::assertSame('needs_investigation', $assessment['verdict']);
            self::assertSame('unknown', $assessment['patch_status']);
        } finally {
            $this->removeDirectory($temporaryRoot);
        }
    }

    public function test_cve_115560_configuration_is_bound_to_the_exact_fpm_runtime_path(): void
    {
        $inventory = $this->collectInventory('cve115560-config');
        $localWorker = $this->fpmPoolWorker($inventory, 'www');
        $localSubjectId = $localWorker['id'];
        $systemWorker = $inventory['workers'][0];
        $systemWorker['id'] = 'worker-124-12345';
        $systemWorker['pid'] = 124;
        $systemWorker['process_name'] = 'php-fpm8.2';
        $systemWorker['executable_path'] = '/usr/sbin/php-fpm8.2';
        $inventory['workers'][] = $systemWorker;

        [, $evaluation] = $this->evaluateInventory($inventory);
        /** @var RuntimeAuditReport $report */
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);
        $advisoryAssessments = array_values(array_filter(
            $evaluation['assessments'],
            static fn(array $assessment): bool => str_starts_with($assessment['record_id'], 'assessment:CVE-2026-115560:'),
        ));
        $localAssessment = $this->assessmentForSubject($evaluation, 'CVE-2026-115560', $localSubjectId);
        $systemAssessment = $this->assessmentForSubject($evaluation, 'CVE-2026-115560', 'worker-124-12345');

        self::assertNotEmpty($advisoryAssessments);
        self::assertIsArray($localAssessment);
        self::assertIsArray($systemAssessment);
        self::assertSame('needs_investigation', $localAssessment['verdict']);
        self::assertSame('unknown', $systemAssessment['verdict']);
        self::assertSame('unknown', $systemAssessment['patch_status']);
        self::assertSame([], $systemAssessment['patch_evidence_ids']);
        self::assertNotEmpty($report['records']);

        $facts = $this->factMap($evaluation);
        $localBasis = $facts['advisory.CVE-2026-115560.' . $localSubjectId . '.assessment_basis'];
        $systemBasis = $facts['advisory.CVE-2026-115560.worker-124-12345.assessment_basis'];
        self::assertIsArray($localBasis);
        self::assertIsArray($systemBasis);
        $configurationFactIds = [
            'fact.configuration.fpm.session.upload_progress.enabled',
            'fact.configuration.fpm.session.serialize_handler',
        ];
        self::assertSame('fact.worker.2.executable_path', $localBasis['runtime_path_fact_id']);
        self::assertSame($configurationFactIds, $localBasis['configuration_fact_ids']);
        self::assertSame([], $systemBasis['configuration_fact_ids']);
        $inventoryFactIds = array_column($inventory['facts'], 'fact_id');
        foreach ($configurationFactIds as $configurationFactId) {
            self::assertContains($configurationFactId, $inventoryFactIds);
        }
        self::assertContains(
            '/usr/local/etc/php-fpm.d/zz-security.conf',
            $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled']['files'],
        );
        self::assertContains(
            '/usr/local/etc/php-fpm.d/zz-security.conf',
            $inventory['configuration_by_sapi']['fpm']['session.serialize_handler']['files'],
        );
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
        $fixedInventory = $this->collectInventory('synthetic-debian-integrity');
        [, $fixedEvaluation] = $this->evaluateInventory($fixedInventory);
        $unverifiedInventory = $this->collectInventory('debian-fpm');
        [, $unverifiedEvaluation] = $this->evaluateInventory($unverifiedInventory);
        $vulnerableFacts = $this->factMap($vulnerableEvaluation);
        $fixedFacts = $this->factMap($fixedEvaluation);
        $unverifiedFacts = $this->factMap($unverifiedEvaluation);

        $vulnerableSubjectId = $vulnerableInventory['workers'][0]['id'];
        $fixedSubjectId = $fixedInventory['workers'][0]['id'];
        $unverifiedSubjectId = $unverifiedInventory['workers'][0]['id'];
        self::assertIsString($vulnerableSubjectId);
        self::assertSame('true', $vulnerableFacts['advisory.CVE-2026-109618.' . $vulnerableSubjectId . '.applicability']);
        self::assertSame('true', $vulnerableFacts['advisory.CVE-2026-109619.' . $vulnerableSubjectId . '.applicability']);
        self::assertSame('false', $fixedFacts['advisory.CVE-2026-109618.' . $fixedSubjectId . '.applicability']);
        self::assertSame('false', $fixedFacts['advisory.CVE-2026-109619.' . $fixedSubjectId . '.applicability']);
        self::assertSame('unknown', $unverifiedFacts['advisory.CVE-2026-109618.' . $unverifiedSubjectId . '.applicability']);
        self::assertSame('unknown', $unverifiedFacts['advisory.CVE-2026-109619.' . $unverifiedSubjectId . '.applicability']);
    }

    public function test_cve_115560_applicability_keeps_runtime_application_condition_unknown(): void
    {
        [$inactiveInventory, $inactiveEvaluation] = $this->evaluate('debian-fpm');
        [$configurationInventory, $configurationEvaluation] = $this->evaluate('cve115560-config');
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

        self::assertSame('unknown', $inactiveFacts['advisory.CVE-2026-115560.' . $inactiveInventory['workers'][0]['id'] . '.applicability']);
        self::assertSame('unknown', $configurationFacts['advisory.CVE-2026-115560.' . $configurationInventory['workers'][0]['id'] . '.applicability']);
        self::assertSame('unknown', $otherSerializerFacts['advisory.CVE-2026-115560.' . $otherSerializerInventory['workers'][0]['id'] . '.applicability']);
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

    public function test_unnamed_fpm_master_does_not_inherit_named_pool_configuration(): void
    {
        $inventory = $this->collectInventory('cve115560-config');
        $master = $inventory['workers'][0];
        self::assertNull($master['fpm_pool_name']);
        $poolWorker = $this->fpmPoolWorker($inventory, 'www');
        self::assertSame($master['pid'], $poolWorker['parent_pid']);

        [, $evaluation] = $this->evaluateInventory($inventory);
        $masterAssessment = $this->assessmentForSubject($evaluation, 'CVE-2026-115560', $master['id']);
        $poolAssessment = $this->assessmentForSubject($evaluation, 'CVE-2026-115560', $poolWorker['id']);

        self::assertIsArray($masterAssessment);
        self::assertSame('unknown', $masterAssessment['verdict']);
        self::assertIsArray($poolAssessment);
        self::assertSame('needs_investigation', $poolAssessment['verdict']);
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

        /** @var RuntimeAuditReport $report */
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);
        $reportSources = $this->reportSourceMap($report);
        $expectedSourceIds = [];
        foreach (array_merge($inventory['sources'], $evaluation['sources']) as $source) {
            $expectedSourceIds[] = $source['source_id'];
        }
        self::assertSame([], array_values(array_diff($expectedSourceIds, array_keys($reportSources))));
        $integritySourceIds = $inventory['workers'][0]['package_provenance']['evidence_source_ids'];
        self::assertCount(4, $integritySourceIds);
        foreach ($integritySourceIds as $sourceId) {
            self::assertArrayHasKey($sourceId, $reportSources);
        }
        $integritySourceLocators = array_map(
            static fn(string $sourceId): mixed => $reportSources[$sourceId]['locator'],
            $integritySourceIds,
        );
        foreach ([
            '/var/lib/dpkg/status',
            '/var/lib/dpkg/info/php8.2-fpm.md5sums',
            '/usr/sbin/php-fpm8.2:fingerprint',
            '/proc/123/exe:fingerprint',
        ] as $locator) {
            self::assertContains($locator, $integritySourceLocators);
        }

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

    public function test_report_retains_raw_configuration_source_and_digest(): void
    {
        [$inventory, $evaluation] = $this->evaluate('cve115560-config');
        /** @var RuntimeAuditReport $report */
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);

        $configurationSource = null;
        foreach ($inventory['sources'] as $source) {
            if ($source['locator'] === '/usr/local/etc/php-fpm.d/zz-security.conf') {
                $configurationSource = $source;
                break;
            }
        }
        self::assertNotNull($configurationSource);

        $reportSources = $this->reportSourceMap($report);
        $expectedSourceIds = [];
        foreach (array_merge($inventory['sources'], $evaluation['sources']) as $source) {
            $expectedSourceIds[] = $source['source_id'];
        }
        self::assertSame([], array_values(array_diff($expectedSourceIds, array_keys($reportSources))));
        self::assertArrayHasKey($configurationSource['source_id'], $reportSources);
        self::assertSame(
            $configurationSource['captured_digest'],
            $reportSources[$configurationSource['source_id']]['captured_digest'],
        );
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

    /**
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-return RuntimeInventory['workers'][int]
     */
    private function fpmPoolWorker(array $inventory, string $poolName): array
    {
        foreach ($inventory['workers'] as $worker) {
            if ($worker['kind'] === 'fpm' && $worker['fpm_pool_name'] === $poolName) {
                return $worker;
            }
        }

        throw new \LogicException('Missing FPM worker for pool ' . $poolName . '.');
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
        } elseif ($name === 'synthetic-debian-apache-integrity') {
            $temporaryRoot = sys_get_temp_dir() . '/pra-advisory-apache-integrity-' . bin2hex(random_bytes(8));
            $this->copyDirectory($fixtureRoot, $temporaryRoot);
            $this->materializeApacheProcLinks($temporaryRoot);
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

    private function materializeApacheProcLinks(string $root): void
    {
        foreach ([
            '/proc/789/ns/mnt',
            '/proc/self/ns/mnt',
            '/proc/789/root',
            '/proc/self/root',
        ] as $relativePath) {
            $path = $root . $relativePath;
            $target = file_get_contents($path);
            self::assertIsString($target);
            self::assertNotSame('', trim($target));
            unlink($path);
            self::assertTrue(symlink(trim($target), $path));
        }
    }

    /** @phpstan-return RuntimeInventory */
    private function collectInventoryWithMixedApacheModuleDeletion(): array
    {
        $fixtureRoot = dirname(__DIR__) . '/fixtures/runtime/ubuntu-apache';
        $temporaryRoot = sys_get_temp_dir() . '/pra-apache-mixed-deleted-' . bin2hex(random_bytes(8));
        $this->copyDirectory($fixtureRoot, $temporaryRoot);
        $mapsPath = $temporaryRoot . '/proc/456/maps';
        $maps = file_get_contents($mapsPath);
        self::assertIsString($maps);
        file_put_contents(
            $mapsPath,
            $maps . "7f000100-7f001000 r-xp 00000000 08:01 12346 /usr/lib/apache2/modules/libphp8.2.so (deleted)\n",
        );

        try {
            return (new RuntimeInventoryCollector(
                new FixtureProcessRunner($temporaryRoot),
                $temporaryRoot,
                '2026-10-25T00:00:00Z',
            ))->collect();
        } finally {
            $this->removeDirectory($temporaryRoot);
        }
    }

    /** @phpstan-return RuntimeInventory */
    private function collectInventoryWithApacheModule(string $modulePath, ?string $distributionOverride = null): array
    {
        $fixtureRoot = dirname(__DIR__) . '/fixtures/runtime/ubuntu-apache';
        $temporaryRoot = sys_get_temp_dir() . '/pra-apache-module-layout-' . bin2hex(random_bytes(8));
        $this->copyDirectory($fixtureRoot, $temporaryRoot);
        $mapsPath = $temporaryRoot . '/proc/456/maps';
        $maps = file_get_contents($mapsPath);
        self::assertIsString($maps);
        self::assertStringContainsString('/usr/lib/apache2/modules/libphp8.3.so', $maps);
        file_put_contents($mapsPath, str_replace('/usr/lib/apache2/modules/libphp8.3.so', $modulePath, $maps));
        if ($distributionOverride !== null) {
            file_put_contents(
                $temporaryRoot . '/etc/os-release',
                'ID=' . $distributionOverride . "\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n",
            );
        }

        try {
            return (new RuntimeInventoryCollector(
                new FixtureProcessRunner($temporaryRoot),
                $temporaryRoot,
                '2026-10-25T00:00:00Z',
            ))->collect();
        } finally {
            $this->removeDirectory($temporaryRoot);
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
            if ($entry->isLink()) {
                $linkTarget = readlink($entry->getPathname());
                if (is_string($linkTarget)) {
                    symlink($linkTarget, $target);
                }
            } elseif ($entry->isDir()) {
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

    /** @phpstan-param RuntimeAuditReport $report */
    private function countReportFactsWithPrefix(array $report, string $prefix): int
    {
        $count = 0;
        foreach ($report['records'] as $record) {
            if (($record['record_type'] ?? null) !== 'observation' || !is_array($record['facts'] ?? null)) {
                continue;
            }
            foreach ($record['facts'] as $fact) {
                if (is_array($fact) && is_string($fact['key'] ?? null) && str_starts_with($fact['key'], $prefix)) {
                    ++$count;
                }
            }
        }

        return $count;
    }

    /** @phpstan-param RuntimeAuditReport $report
     * @return array<string, array<string, mixed>>
     */
    private function reportSourceMap(array $report): array
    {
        /** @var array<string, array<string, mixed>> $sources */
        $sources = [];
        foreach ($report['records'] as $record) {
            if (($record['record_type'] ?? null) !== 'observation' || !is_array($record['sources'] ?? null)) {
                continue;
            }
            foreach ($record['sources'] as $source) {
                if (!is_array($source)) {
                    continue;
                }
                $sourceId = $source['source_id'] ?? null;
                if (!is_string($sourceId)) {
                    continue;
                }
                /** @var array<string, mixed> $sourceRecord */
                $sourceRecord = $source;
                $sources[$sourceId] = $sourceRecord;
            }
        }

        return $sources;
    }

    /** @phpstan-param RuntimeInventory $inventory */
    private function appendCliRuntime(array &$inventory, string $binaryPath, string $version, int $runtimeIndex): string
    {
        $sourceId = null;
        foreach ($inventory['facts'] as $fact) {
            if ($fact['key'] === 'runtime.cli.1.version') {
                $sourceId = $fact['source_id'];
                break;
            }
        }
        if (!is_string($sourceId)) {
            throw new \LogicException('The fixture must include a CLI version source.');
        }

        $runtimeId = 'cli-' . substr(hash('sha256', $binaryPath), 0, 20);
        $inventory['runtimes'][] = [
            'id' => $runtimeId,
            'kind' => 'cli',
            'binary_path' => $binaryPath,
            'version' => $version,
            'sapi' => 'cli',
            'extensions' => [],
        ];
        $runtimeFacts = [
            'version' => $version,
            'id' => $runtimeId,
            'sapi' => 'cli',
            'binary_path' => $binaryPath,
            'extensions' => [],
        ];
        foreach ($runtimeFacts as $name => $value) {
            $key = 'runtime.cli.' . $runtimeIndex . '.' . $name;
            $inventory['facts'][] = [
                'fact_id' => 'fact.' . $key,
                'key' => $key,
                'value' => $value,
                'source_id' => $sourceId,
            ];
        }

        return $runtimeId;
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

    /**
     * @phpstan-param AdvisoryEvaluation $evaluation
     * @phpstan-return AdvisoryAssessment|null
     */
    private function assessmentForSubject(array $evaluation, string $cve, string $subjectId): ?array
    {
        foreach ($evaluation['assessments'] as $assessment) {
            if ($assessment['subject_id'] === $subjectId
                && str_starts_with($assessment['record_id'], 'assessment:' . $cve . ':')) {
                return $assessment;
            }
        }

        return null;
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

    /**
     * @param list<string> $command
     * @return array{stdout: string, stderr: string, exit: int}
     */
    private function runCli(array $command, string $stdin): array
    {
        $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, dirname(__DIR__, 2));
        self::assertIsResource($process);
        fwrite($pipes[0], $stdin);
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exit = proc_close($process);

        self::assertIsString($stdout);
        self::assertIsString($stderr);

        return ['stdout' => $stdout, 'stderr' => $stderr, 'exit' => $exit];
    }
}
