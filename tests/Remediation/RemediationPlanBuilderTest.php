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
