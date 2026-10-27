<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Remediation;

/** Renders a RemediationPlan as a human-readable REPORT.md. Pure text formatting; no I/O. */
final class RemediationReportMarkdownRenderer
{
    public function render(RemediationPlan $plan): string
    {
        $lines = [
            '# PHP Runtime Audit remediation report',
            '',
            sprintf('Generated: %s', SafeText::markdown($plan->generatedAt)),
            sprintf('Distribution: %s', $plan->distribution !== null ? SafeText::markdown($plan->distribution) : '_unknown_'),
            '',
            '**This report proposes reviewable changes only. Nothing in it has been applied. Every action requires explicit human approval before execution, and this tool never runs, restarts, installs, or modifies anything on your behalf.**',
            '',
        ];

        if ($plan->warnings !== []) {
            $lines[] = '## Report warnings';
            $lines[] = '';
            foreach ($plan->warnings as $warning) {
                $lines[] = sprintf('- %s', SafeText::markdown($warning, 256));
            }
            $lines[] = '';
        }

        if ($plan->actions === []) {
            $lines[] = 'No remediation proposals were generated from this report.';

            return implode("\n", $lines) . "\n";
        }

        foreach ($plan->actions as $action) {
            $lines[] = sprintf('## %s — %s', SafeText::markdown($action->cve), SafeText::markdown($action->subjectLabel));
            $lines[] = '';
            $lines[] = sprintf('- **Subject:** `%s`', SafeText::plain($action->subjectId, 128));
            $lines[] = sprintf('- **Advisory:** %s', SafeText::markdown($action->advisoryTitle));
            $lines[] = sprintf('- **Kind:** `%s`', $action->kind->value);
            $lines[] = '- **Requires human approval:** yes';
            $lines[] = sprintf('- **Maintenance window likely needed:** %s', $action->maintenanceWindowRequired ? 'yes' : 'no');
            $lines[] = '';
            $lines[] = sprintf('**WHY**  %s', SafeText::markdown($action->why, 1024));
            $lines[] = '';
            $lines[] = '**EVIDENCE**';
            if ($action->evidenceIds === []) {
                $lines[] = '- _No specific evidence facts were cited for this subject._';
            } else {
                foreach ($action->evidenceIds as $evidenceId) {
                    $lines[] = sprintf('- `%s`', SafeText::plain($evidenceId, 128));
                }
            }
            $lines[] = '';
            $lines[] = '**PREREQUISITES**';
            if ($action->prerequisites === []) {
                $lines[] = '- _None._';
            } else {
                foreach ($action->prerequisites as $prerequisite) {
                    $lines[] = sprintf('- %s', SafeText::markdown($prerequisite, 512));
                }
            }
            $lines[] = '';
            $lines[] = sprintf('**ACTION**  %s', SafeText::markdown($action->action, 1024));
            $lines[] = '';
            $lines[] = sprintf('**RISK**  %s', SafeText::markdown($action->risk, 512));
            $lines[] = '';
            $lines[] = sprintf('**ROLLBACK**  %s', SafeText::markdown($action->rollback, 512));
            $lines[] = '';
            $lines[] = sprintf('**VERIFICATION**  %s', SafeText::markdown($action->verification, 512));
            $lines[] = '';
            $lines[] = '**UNKNOWN**';
            if ($action->unknowns === []) {
                $lines[] = '- _Nothing outstanding._';
            } else {
                foreach ($action->unknowns as $unknown) {
                    $lines[] = sprintf('- %s', SafeText::markdown($unknown, 512));
                }
            }
            $lines[] = '';
            $lines[] = '---';
            $lines[] = '';
        }

        return implode("\n", $lines) . "\n";
    }
}
