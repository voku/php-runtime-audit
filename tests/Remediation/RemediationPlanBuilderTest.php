<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\Remediation;

use PHPUnit\Framework\TestCase;
use voku\PhpRuntimeAudit\Advisories\AdvisoryCatalog;
use voku\PhpRuntimeAudit\Advisories\AdvisoryEvaluator;
use voku\PhpRuntimeAudit\Advisories\RuntimeAuditReportBuilder;
use voku\PhpRuntimeAudit\Remediation\RemediationActionKind;
use voku\PhpRuntimeAudit\Remediation\RemediationPlanBuilder;
use voku\PhpRuntimeAudit\Remediation\RemediationPlan;
use voku\PhpRuntimeAudit\Remediation\RemediationReportMarkdownRenderer;
use voku\PhpRuntimeAudit\RuntimeInventory\FixtureProcessRunner;
use voku\PhpRuntimeAudit\RuntimeInventory\RuntimeInventoryCollector;

/**
 * @phpstan-import-type RuntimeInventory from RuntimeInventoryCollector
 */
final class RemediationPlanBuilderTest extends TestCase
{
    public function test_verified_fixed_package_produces_no_action_required_with_no_approval_gap(): void
    {
        $plan = $this->buildPlanFor('debian-fpm');

        $verifiedFixed = array_values(array_filter(
            $plan->actions,
            static fn($action): bool => $action->kind === RemediationActionKind::NoActionRequired,
        ));
        self::assertNotEmpty($verifiedFixed, 'debian-fpm should produce at least one verified_fixed package assessment.');
        foreach ($verifiedFixed as $action) {
            self::assertTrue($action->requiresHumanApproval);
            self::assertSame('Not applicable.', $action->rollback);
            self::assertNotEmpty($action->evidenceIds, 'A verified_fixed action should still cite the evidence that established it.');
        }
    }

    public function test_verified_fixed_missing_patch_evidence_never_produces_no_action_required(): void
    {
        $inventory = $this->collectInventory('debian-fpm');
        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);

        $targetIndex = null;
        $targetId = null;
        $subjectId = null;
        foreach ($report['records'] as $index => $record) {
            if (($record['record_type'] ?? null) !== 'assessment'
                || ($record['verdict'] ?? null) !== 'verified_fixed'
                || !is_string($record['subject_id'] ?? null)
                || !str_starts_with($record['subject_id'], 'package-')) {
                continue;
            }
            $targetIndex = $index;
            $targetId = $record['record_id'];
            $subjectId = $record['subject_id'];
            break;
        }
        self::assertNotNull($targetIndex, 'The fixture must contain a verified fixed package assessment.');
        self::assertIsString($targetId);
        self::assertIsString($subjectId);

        foreach ([[], ['fact.nonexistent.patch-evidence']] as $unresolvedEvidenceIds) {
            $mutated = $report;
            $mutated['records'][$targetIndex]['patch_evidence_ids'] = $unresolvedEvidenceIds;
            $plan = (new RemediationPlanBuilder())->build($mutated);
            $actions = array_values(array_filter(
                $plan->actions,
                static fn($action): bool => $action->subjectId === $subjectId
                    && $action->cve === explode(':', $targetId)[1],
            ));

            self::assertCount(1, $actions);
            self::assertSame(RemediationActionKind::AwaitVendorEvidence, $actions[0]->kind);
            self::assertNotEmpty($actions[0]->evidenceIds, 'Identity facts should still resolve, but not serve as patch proof.');
            self::assertStringContainsString('no resolvable patch evidence', implode(' ', $plan->warnings));
            self::assertFalse($plan->toArray()['automatic_apply']);
        }
    }

    public function test_potentially_affected_worker_produces_upgrade_proposal_with_full_fields(): void
    {
        $plan = $this->buildPlanFor('debian-fpm-vulnerable');

        $upgrades = array_values(array_filter(
            $plan->actions,
            static fn($action): bool => $action->kind === RemediationActionKind::UpgradePackage,
        ));
        self::assertNotEmpty($upgrades, 'debian-fpm-vulnerable should produce at least one potentially_affected proposal.');
        foreach ($upgrades as $action) {
            self::assertTrue($action->requiresHumanApproval);
            self::assertTrue($action->maintenanceWindowRequired);
            self::assertNotSame('', $action->why);
            self::assertNotEmpty($action->prerequisites);
            self::assertNotSame('', $action->action);
            self::assertNotSame('', $action->risk);
            self::assertNotSame('', $action->rollback);
            self::assertNotSame('', $action->verification);
            self::assertStringNotContainsString('rm -rf', $action->action);
            self::assertStringNotContainsString(';', $action->action, 'The action text must never read like a shell command.');
        }
    }

    public function test_needs_investigation_configuration_never_claims_a_patch_verdict(): void
    {
        $plan = $this->buildPlanFor('rhel10-fpm-pool-override');

        $investigations = array_values(array_filter(
            $plan->actions,
            static fn($action): bool => $action->kind === RemediationActionKind::InvestigateConfiguration,
        ));
        self::assertNotEmpty($investigations, 'rhel10-fpm-pool-override should produce a needs_investigation proposal.');
        foreach ($investigations as $action) {
            self::assertStringNotContainsString('verified_fixed', strtolower($action->action));
            self::assertStringContainsString('review', strtolower($action->action));
        }
    }

    public function test_configuration_investigation_cites_target_configuration_facts_in_action_and_markdown(): void
    {
        $inventory = $this->collectInventory('rhel10-fpm-pool-override');
        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);
        $factsById = [];
        $factsByKey = [];
        $assessment = null;
        foreach ($report['records'] as $record) {
            $recordSubjectId = $record['subject_id'] ?? null;
            if (($record['record_type'] ?? null) === 'assessment'
                && is_string($recordSubjectId)
                && ($record['record_id'] ?? null) === 'assessment:CVE-2026-115560:' . $recordSubjectId
                && ($record['verdict'] ?? null) === 'needs_investigation') {
                $assessment = $record;
            }
            $facts = ($record['record_type'] ?? null) === 'observation' ? ($record['facts'] ?? null) : null;
            if (!is_array($facts)) {
                continue;
            }
            foreach ($facts as $fact) {
                if (!is_array($fact) || !is_string($fact['fact_id'] ?? null) || !is_string($fact['key'] ?? null)) {
                    continue;
                }
                $factsById[$fact['fact_id']] = $fact;
                $factsByKey[$fact['key']] = $fact;
            }
        }

        self::assertIsArray($assessment);
        $subjectId = $assessment['subject_id'] ?? null;
        self::assertIsString($subjectId);
        $basis = $factsByKey['advisory.CVE-2026-115560.' . $subjectId . '.assessment_basis'] ?? null;
        self::assertIsArray($basis);
        $basisValue = $basis['value'] ?? null;
        if ($basisValue instanceof \stdClass) {
            $basisValue = get_object_vars($basisValue);
        }
        self::assertIsArray($basisValue);
        $configurationFactIds = $basisValue['configuration_fact_ids'] ?? null;
        self::assertIsArray($configurationFactIds);
        self::assertNotEmpty($configurationFactIds);

        $plan = (new RemediationPlanBuilder())->build($report);
        $action = null;
        foreach ($plan->actions as $candidate) {
            if ($candidate->subjectId === $subjectId && $candidate->cve === 'CVE-2026-115560') {
                $action = $candidate;
                break;
            }
        }
        self::assertNotNull($action);
        self::assertSame(RemediationActionKind::InvestigateConfiguration, $action->kind);

        $markdown = (new RemediationReportMarkdownRenderer())->render($plan);
        foreach ($configurationFactIds as $configurationFactId) {
            self::assertIsString($configurationFactId);
            $configurationFact = $factsById[$configurationFactId] ?? null;
            self::assertIsArray($configurationFact);
            self::assertStringStartsWith('configuration.target.', $configurationFact['key']);
            self::assertStringContainsString('.fpm.', $configurationFact['key']);
            self::assertContains($configurationFactId, $action->evidenceIds);
            self::assertStringContainsString('`' . $configurationFactId . '`', $markdown);
        }
    }

    public function test_fpm_remediation_citations_are_scoped_to_each_runtime_configuration_root(): void
    {
        $inventory = $this->collectInventory('cve115560-config');
        $secondWorker = $inventory['workers'][0];
        $secondWorker['id'] = 'worker-805-54321';
        $secondWorker['pid'] = 805;
        $secondWorker['parent_pid'] = null;
        $secondWorker['process_name'] = 'php-fpm8.3';
        $secondWorker['executable_path'] = '/usr/sbin/php-fpm8.3';
        $secondWorker['version'] = '8.3.5';
        $secondWorker['fpm_configuration_path'] = null;
        $secondWorker['fpm_configuration_state'] = 'default';
        $secondWorker['fpm_pool_name'] = null;
        $inventory['workers'][] = $secondWorker;

        $secondRoot = '/etc/php/8.3/fpm';
        $secondFile = $secondRoot . '/php.ini';
        $uploadSetting = $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled'];
        $uploadSetting['observations'][] = [
            'value' => '1',
            'file' => $secondFile,
            'context' => 'global',
            'configuration_root' => $secondRoot,
        ];
        $uploadSetting['files'][] = $secondFile;
        $uploadSetting['state'] = 'conflict';
        $uploadSetting['value'] = null;
        $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled'] = $uploadSetting;

        $serializeSetting = $inventory['configuration_by_sapi']['fpm']['session.serialize_handler'];
        $serializeSetting['observations'][] = [
            'value' => 'php_serialize',
            'file' => $secondFile,
            'context' => 'global',
            'configuration_root' => $secondRoot,
        ];
        $serializeSetting['files'][] = $secondFile;
        $serializeSetting['state'] = 'conflict';
        $serializeSetting['value'] = null;
        $inventory['configuration_by_sapi']['fpm']['session.serialize_handler'] = $serializeSetting;

        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);
        $plan = (new RemediationPlanBuilder())->build($report);
        $actions = array_values(array_filter(
            $plan->actions,
            static fn($action): bool => $action->cve === 'CVE-2026-115560'
                && $action->kind === RemediationActionKind::InvestigateConfiguration,
        ));
        $factsById = [];
        $factsByKey = [];
        foreach ($evaluation['facts'] as $fact) {
            $factsById[$fact['fact_id']] = $fact;
            $factsByKey[$fact['key']] = $fact['value'];
        }
        $expectedRoots = [];
        foreach (array_slice($inventory['workers'], 0, -1) as $worker) {
            $expectedRoots[$worker['id']] = '/usr/local/etc';
        }
        $expectedRoots[$secondWorker['id']] = $secondRoot;

        self::assertNotEmpty($actions);
        $rootsCovered = [];
        foreach ($actions as $action) {
            $expectedRoot = $expectedRoots[$action->subjectId] ?? null;
            self::assertIsString($expectedRoot, 'An FPM remediation action must resolve to a known worker runtime.');
            $basis = $factsByKey['advisory.CVE-2026-115560.' . $action->subjectId . '.assessment_basis'] ?? null;
            self::assertIsArray($basis);
            $configurationFactIds = $basis['configuration_fact_ids'] ?? null;
            self::assertIsArray($configurationFactIds);
            self::assertNotEmpty($configurationFactIds);
            foreach ($configurationFactIds as $configurationFactId) {
                self::assertIsString($configurationFactId);
                $configurationFact = $factsById[$configurationFactId] ?? null;
                self::assertIsArray($configurationFact);
                self::assertContains($configurationFactId, $action->evidenceIds);
                $configurationValue = $configurationFact['value'];
                if ($configurationValue instanceof \stdClass) {
                    $configurationValue = get_object_vars($configurationValue);
                }
                self::assertIsArray($configurationValue);
                $observations = $configurationValue['observations'] ?? null;
                self::assertIsArray($observations);
                self::assertNotEmpty($observations);
                foreach ($observations as $observation) {
                    self::assertIsArray($observation);
                    self::assertSame($expectedRoot, $observation['configuration_root']);
                }
            }
            $rootsCovered[$expectedRoot] = true;
        }

        self::assertArrayHasKey('/usr/local/etc', $rootsCovered);
        self::assertArrayHasKey($secondRoot, $rootsCovered);
    }

    public function test_unknown_subject_evidence_and_unknown_vendor_status_use_different_kinds(): void
    {
        $plan = $this->buildPlanFor('alpine-fpm');

        $kinds = array_map(static fn($action): string => $action->kind->value, $plan->actions);
        self::assertContains(RemediationActionKind::AwaitVendorEvidence->value, $kinds);
        foreach ($plan->actions as $action) {
            if ($action->kind !== RemediationActionKind::AwaitVendorEvidence) {
                continue;
            }
            self::assertNotEmpty($action->unknowns);
            self::assertNotEmpty($action->prerequisites);
        }
    }

    public function test_every_action_requires_human_approval_and_proposes_no_automatic_change(): void
    {
        foreach (['debian-fpm', 'debian-fpm-vulnerable', 'rhel10-fpm-pool-override', 'alpine-fpm', 'ubuntu-apache'] as $fixture) {
            $plan = $this->buildPlanFor($fixture);
            foreach ($plan->actions as $action) {
                self::assertTrue($action->requiresHumanApproval, $fixture . ' produced an action that does not require approval.');
            }
            self::assertFalse($plan->toArray()['automatic_apply']);
        }
    }

    public function test_evidence_ids_only_ever_reference_facts_actually_present_in_the_report(): void
    {
        $inventory = $this->collectInventory('debian-fpm');
        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);

        $knownFactIds = [];
        foreach ($report['records'] as $record) {
            $facts = ($record['record_type'] ?? null) === 'observation' ? ($record['facts'] ?? null) : null;
            if (!is_array($facts)) {
                continue;
            }
            foreach ($facts as $fact) {
                if (is_array($fact) && is_string($fact['fact_id'] ?? null)) {
                    $knownFactIds[$fact['fact_id']] = true;
                }
            }
        }

        $plan = (new RemediationPlanBuilder())->build($report);
        foreach ($plan->actions as $action) {
            foreach ($action->evidenceIds as $evidenceId) {
                self::assertArrayHasKey($evidenceId, $knownFactIds, 'A remediation action cited an evidence_id not present in the report.');
            }
        }
    }

    public function test_inactive_fpm_executable_subject_resolves_from_runtime_facts(): void
    {
        $inventory = $this->collectInventory('debian-fpm');
        $executable = $inventory['fpm_executables'][0];
        $inventory['workers'] = [];
        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);
        $plan = (new RemediationPlanBuilder())->build($report);

        $actions = array_values(array_filter(
            $plan->actions,
            static fn($action): bool => $action->subjectId === $executable['id'],
        ));

        self::assertNotEmpty($actions, 'The inactive FPM executable should have remediation proposals for its assessments.');
        foreach ($actions as $action) {
            self::assertStringNotContainsString('Unrecognized runtime subject', $action->subjectLabel);
            self::assertStringContainsString($executable['binary_path'], $action->subjectLabel);
            self::assertNotEmpty($action->evidenceIds);
        }
    }

    public function test_remediation_resolves_citations_and_subject_identity_across_report_chunks(): void
    {
        $inventory = $this->collectInventory('debian-fpm');
        $sourceId = $inventory['sources'][0]['source_id'] ?? null;
        self::assertIsString($sourceId);

        /** @var list<array{fact_id: string, key: string, value: int, source_id: string}> $paddingFacts */
        $paddingFacts = [];
        for ($index = 0; $index < 1024; ++$index) {
            $paddingFacts[] = [
                'fact_id' => 'fact.test.padding.' . $index,
                'key' => 'test.padding.' . $index,
                'value' => $index,
                'source_id' => $sourceId,
            ];
        }
        $inventory['facts'] = [...$paddingFacts, ...$inventory['facts']];

        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);
        $observations = array_values(array_filter(
            $report['records'],
            static fn(array $record): bool => ($record['record_type'] ?? null) === 'observation',
        ));
        self::assertGreaterThan(1, count($observations));

        /** @var array<string, true> $laterFactIds */
        $laterFactIds = [];
        foreach (array_slice($observations, 1) as $observation) {
            $facts = $observation['facts'] ?? null;
            if (!is_array($facts)) {
                continue;
            }
            foreach ($facts as $fact) {
                $factId = is_array($fact) ? ($fact['fact_id'] ?? null) : null;
                if (is_string($factId)) {
                    $laterFactIds[$factId] = true;
                }
            }
        }

        /** @var array<string, mixed>|null $assessment */
        $assessment = null;
        foreach ($report['records'] as $record) {
            $subjectId = $record['subject_id'] ?? null;
            if (($record['record_type'] ?? null) !== 'assessment' || !is_string($subjectId) || $subjectId === 'local-host') {
                continue;
            }
            $patchEvidenceIds = $record['patch_evidence_ids'] ?? null;
            if (!is_array($patchEvidenceIds) || !array_is_list($patchEvidenceIds)) {
                continue;
            }
            foreach ($patchEvidenceIds as $evidenceId) {
                if (!is_string($evidenceId)) {
                    continue;
                }
                if (isset($laterFactIds[$evidenceId])) {
                    $assessment = $record;
                    break 2;
                }
            }
        }
        self::assertIsArray($assessment, 'A runtime subject assessment should cite evidence stored only in a later observation chunk.');
        $subjectId = $assessment['subject_id'] ?? null;
        $recordId = $assessment['record_id'] ?? null;
        $patchEvidenceIds = $assessment['patch_evidence_ids'] ?? null;
        self::assertIsString($subjectId);
        self::assertIsString($recordId);
        self::assertIsArray($patchEvidenceIds);
        $cve = explode(':', $recordId)[1] ?? null;
        self::assertIsString($cve);

        $plan = (new RemediationPlanBuilder())->build($report);
        $action = null;
        foreach ($plan->actions as $candidate) {
            if ($candidate->subjectId === $subjectId && $candidate->cve === $cve) {
                $action = $candidate;
                break;
            }
        }
        self::assertNotNull($action);
        self::assertStringNotContainsString('No matching runtime fact', $action->subjectLabel);
        foreach ($patchEvidenceIds as $evidenceId) {
            if (is_string($evidenceId) && isset($laterFactIds[$evidenceId])) {
                self::assertContains($evidenceId, $action->evidenceIds);
                break;
            }
        }
    }

    public function test_apache_module_subject_resolves_to_a_readable_label(): void
    {
        $plan = $this->buildPlanFor('ubuntu-apache');

        $apacheActions = array_values(array_filter(
            $plan->actions,
            static fn($action): bool => str_starts_with($action->subjectId, 'apache-'),
        ));
        self::assertNotEmpty($apacheActions, 'ubuntu-apache should produce at least one apache-module subject.');
        foreach ($apacheActions as $action) {
            self::assertStringNotContainsString('Unrecognized', $action->subjectLabel);
            self::assertStringNotContainsString('No matching', $action->subjectLabel);
        }
    }

    private function buildPlanFor(string $fixture): RemediationPlan
    {
        $inventory = $this->collectInventory($fixture);
        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());
        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);

        return (new RemediationPlanBuilder())->build($report);
    }

    /** @phpstan-return RuntimeInventory */
    private function collectInventory(string $name): array
    {
        $root = dirname(__DIR__) . '/fixtures/runtime/' . $name;

        return (new RuntimeInventoryCollector(
            new FixtureProcessRunner($root),
            $root,
            '2026-10-25T00:00:00Z',
        ))->collect();
    }
}
