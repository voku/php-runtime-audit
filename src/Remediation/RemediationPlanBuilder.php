<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Remediation;

use voku\PhpRuntimeAudit\Advisories\AdvisoryCatalog;
use voku\PhpRuntimeAudit\Advisories\RuntimeAuditReportBuilder;

/**
 * Builds reviewable remediation proposals from an already-generated runtime audit report.
 *
 * This is a pure transformation: JSON report in, a RemediationPlan out. It never collects new
 * evidence, never executes anything, and never claims an action needs no human approval. The
 * report is treated as untrusted input (it may come from a different host, an older tool
 * version, or a hand-edited file), so every field is type- and shape-checked before use; a
 * record that fails validation is skipped and recorded as a warning rather than guessed at.
 *
 * @phpstan-import-type AdvisoryDefinition from AdvisoryCatalog
 * @phpstan-type ReportFact array{fact_id: string, key: string, value: mixed, source_id: string}
 */
final class RemediationPlanBuilder
{
    private const MAX_RECORDS = RuntimeAuditReportBuilder::MAX_REPORT_RECORDS;
    private const MAX_FACTS = RuntimeAuditReportBuilder::MAX_REPORT_FACTS;

    private readonly AdvisoryCatalog $catalog;

    public function __construct(?AdvisoryCatalog $catalog = null)
    {
        $this->catalog = $catalog ?? AdvisoryCatalog::load();
    }

    /** @param array<string, mixed> $report */
    public function build(array $report): RemediationPlan
    {
        $warnings = [];
        $records = $report['records'] ?? null;
        if (!is_array($records) || !array_is_list($records) || count($records) > self::MAX_RECORDS) {
            return new RemediationPlan(gmdate('Y-m-d\TH:i:s\Z'), null, [], ['The report has no usable records array; no proposals could be built.']);
        }

        $facts = $this->extractFacts($records, $warnings);
        $factsById = [];
        $factsByKey = [];
        foreach ($facts as $fact) {
            $factsById[$fact['fact_id']] = $fact;
            $factsByKey[$fact['key']] = $fact;
        }
        $advisoriesByCve = [];
        foreach ($this->catalog->advisories as $advisory) {
            $advisoriesByCve[$advisory['cve']] = $advisory;
        }

        $actions = [];
        foreach ($records as $record) {
            if (!is_array($record) || ($record['record_type'] ?? null) !== 'assessment') {
                continue;
            }
            /** @var array<string, mixed> $record */
            $action = $this->buildAction($record, $factsById, $factsByKey, $advisoriesByCve, $warnings);
            if ($action !== null) {
                $actions[] = $action;
            }
        }

        $summary = $report['summary'] ?? null;
        $distribution = is_array($summary) ? ($summary['distribution'] ?? null) : null;

        return new RemediationPlan(
            gmdate('Y-m-d\TH:i:s\Z'),
            is_string($distribution) ? SafeText::plain($distribution, 64) : null,
            $actions,
            $warnings,
        );
    }

    /**
     * @param list<mixed> $records
     * @param list<string> $warnings
     * @phpstan-return list<ReportFact>
     */
    private function extractFacts(array $records, array &$warnings): array
    {
        $foundObservation = false;
        $facts = [];
        $seenFactIds = [];
        foreach ($records as $record) {
            if (!is_array($record) || ($record['record_type'] ?? null) !== 'observation') {
                continue;
            }
            $foundObservation = true;
            $rawFacts = $record['facts'] ?? null;
            if (!is_array($rawFacts) || !array_is_list($rawFacts)) {
                $warnings[] = 'The observation record has no usable facts list; evidence citations will be incomplete.';

                continue;
            }
            foreach ($rawFacts as $fact) {
                if (!is_array($fact) || !is_string($fact['fact_id'] ?? null)
                    || !is_string($fact['key'] ?? null) || !is_string($fact['source_id'] ?? null)) {
                    continue;
                }
                if (isset($seenFactIds[$fact['fact_id']])) {
                    continue;
                }
                if (count($facts) >= self::MAX_FACTS) {
                    $warnings[] = 'The report exceeds the supported fact count; evidence citations may be incomplete.';

                    return $facts;
                }
                $facts[] = [
                    'fact_id' => $fact['fact_id'],
                    'key' => $fact['key'],
                    'value' => $fact['value'] ?? null,
                    'source_id' => $fact['source_id'],
                ];
                $seenFactIds[$fact['fact_id']] = true;
            }
        }

        if (!$foundObservation) {
            $warnings[] = 'No observation record was found; evidence citations will be incomplete.';
        }

        return $facts;
    }

    /**
     * @param array<string, mixed> $record
     * @param array<string, ReportFact> $factsById
     * @param array<string, ReportFact> $factsByKey
     * @phpstan-param array<string, AdvisoryDefinition> $advisoriesByCve
     * @param list<string> $warnings
     */
    private function buildAction(array $record, array $factsById, array $factsByKey, array $advisoriesByCve, array &$warnings): ?RemediationAction
    {
        $recordId = $record['record_id'] ?? null;
        $subjectId = $record['subject_id'] ?? null;
        $verdict = $record['verdict'] ?? null;
        $rationale = $record['rationale'] ?? null;
        $patchEvidenceIds = $record['patch_evidence_ids'] ?? null;
        if (!is_string($recordId) || !is_string($subjectId) || $subjectId === ''
            || !is_string($verdict) || !is_string($rationale)
            || !is_array($patchEvidenceIds) || !array_is_list($patchEvidenceIds)) {
            $warnings[] = 'An assessment record is missing required fields and was skipped.';

            return null;
        }
        $parts = explode(':', $recordId, 3);
        if (count($parts) !== 3 || $parts[0] !== 'assessment' || preg_match('/\ACVE-[0-9]{4}-[0-9]{4,}\z/', $parts[1]) !== 1 || $parts[2] !== $subjectId) {
            $warnings[] = 'An assessment record_id is malformed or inconsistent with its subject_id and was skipped.';

            return null;
        }
        $cve = $parts[1];
        $validPatchEvidenceIds = [];
        // The producer uses an internal runtime target ID in advisory fact keys,
        // which may differ from the public assessment subject_id for web workers.
        $assessmentBasisPrefix = 'advisory.' . $cve . '.';
        $hasMatchingPatchBasis = false;
        foreach ($patchEvidenceIds as $evidenceId) {
            if (is_string($evidenceId) && isset($factsById[$evidenceId])) {
                $validPatchEvidenceIds[] = $evidenceId;
                // Identity IDs alone are not patch evidence. Require a
                // referenced assessment-basis fact for this CVE. The basis
                // uses the producer's internal target ID, not necessarily
                // the subject ID exposed in the assessment record.
                $key = $factsById[$evidenceId]['key'];
                if (str_starts_with($key, $assessmentBasisPrefix)
                    && str_ends_with($key, '.assessment_basis')) {
                    $hasMatchingPatchBasis = true;
                }
            } elseif (is_string($evidenceId)) {
                $warnings[] = sprintf('%s cites evidence_id "%s" that does not match any fact in this report; it was dropped.', $cve, SafeText::plain($evidenceId, 64));
            }
        }

        $identity = SubjectIdentity::resolveIndexed($factsByKey, $subjectId);
        // Identity facts identify the subject; they do not establish the patch verdict.
        $validEvidenceIds = array_values(array_unique([...$validPatchEvidenceIds, ...$identity->evidenceIds]));
        if ($verdict === 'needs_investigation') {
            $configurationEvidenceIds = $this->configurationEvidenceIds($cve, $subjectId, $factsById, $factsByKey);
            $validEvidenceIds = array_values(array_unique([...$validEvidenceIds, ...$configurationEvidenceIds]));
        }

        $advisory = $advisoriesByCve[$cve] ?? null;
        $advisoryTitle = $advisory !== null ? SafeText::plain($advisory['title']) : 'Advisory not found in the loaded catalog';
        $sourceNote = $advisory !== null ? sprintf(' See the advisory source for the authoritative fixed version: %s', $advisory['source_url']) : '';

        $actionId = 'remediation.' . $cve . '.' . substr(hash('sha256', $subjectId), 0, 12);
        $safeRationale = SafeText::plain($rationale, 1024);

        $verifiedFixedUnknowns = [
            'A matched package version is not proof the running worker process was restarted since patching.',
            'Host compromise status is tracked independently of patch status and remains unknown regardless of this verdict.',
        ];
        if ($verdict === 'verified_fixed' && !$hasMatchingPatchBasis) {
            $warnings[] = sprintf(
                '%s claims verified_fixed for %s with no resolvable patch evidence (missing this assessment\'s cited patch basis); the remediation recommendation was downgraded to unknown.',
                $cve,
                $subjectId,
            );
            // A warning beside "no_action_required" is not a safe fallback. Do not
            // mistake independently resolved identity facts for proof of a patch.
            $verdict = 'unknown';
            $safeRationale = 'The source assessment claims a fixed build but has no resolvable patch evidence in this report.';
        }

        return match ($verdict) {
            'verified_fixed' => new RemediationAction(
                $actionId,
                $subjectId,
                $identity->label,
                $cve,
                $advisoryTitle,
                RemediationActionKind::NoActionRequired,
                sprintf('%s (%s): current evidence matches a vendor-fixed build for this subject. %s', $advisoryTitle, $cve, $safeRationale),
                $validEvidenceIds,
                [],
                'No remediation action is required for this subject based on current evidence.',
                'None; this is a no-action recommendation.',
                'Not applicable.',
                'Re-run the audit after any future change and confirm patch_status remains verified_fixed.',
                $verifiedFixedUnknowns,
                false,
            ),
            'potentially_affected' => new RemediationAction(
                $actionId,
                $subjectId,
                $identity->label,
                $cve,
                $advisoryTitle,
                RemediationActionKind::UpgradePackage,
                sprintf('%s (%s): current evidence is below the sourced fixed build for this subject. %s', $advisoryTitle, $cve, $safeRationale),
                $validEvidenceIds,
                [
                    'Confirm a maintenance window with stakeholders before changing production PHP packages.',
                    'Record the currently installed package version so the change can be reversed.',
                    'Confirm the vendor-published fixed version against the advisory source before proceeding.',
                ],
                'Upgrade the vendor-maintained PHP package identified for this subject to the fixed version published in the advisory, using your distribution\'s normal package manager.' . $sourceNote,
                'Upgrading a PHP package can restart PHP-FPM or Apache workers and interrupt in-flight requests; a version change may also alter other runtime behavior.',
                'Keep the previously installed package version recorded before upgrading so it can be reinstalled if the change causes a regression; validate any downgrade procedure outside production first.',
                'After upgrading and restarting the affected worker, re-run this tool and confirm this subject\'s patch_status becomes verified_fixed against fresh evidence; separately confirm application behavior.',
                [
                    'Whether a vendor-specific backport beyond the catalogued rule already applies to this exact package build.',
                    'Whether other configuration in this environment needs to change as part of the same maintenance window.',
                ],
                true,
            ),
            'needs_investigation' => new RemediationAction(
                $actionId,
                $subjectId,
                $identity->label,
                $cve,
                $advisoryTitle,
                RemediationActionKind::InvestigateConfiguration,
                sprintf('%s (%s): evidence shows a configuration or process condition that needs human review; this is not a confirmed patch verdict. %s', $advisoryTitle, $cve, $safeRationale),
                $validEvidenceIds,
                ['Review the cited configuration evidence against your organization\'s hardening baseline before changing anything.'],
                'Have an administrator manually review the cited configuration and process evidence; do not change production configuration automatically.',
                'Manually changing session, upload, or pool configuration can affect running applications that depend on current behavior, and reloading a worker to apply a configuration change causes a brief interruption.',
                'Keep a copy of the current configuration file before making any change.',
                'After any configuration change, reload the affected worker, re-run this tool, and confirm the relevant configuration facts reflect the intended state.',
                [
                    'Whether this configuration is intentional for this environment.',
                    'Patch status for this subject is tracked independently of this configuration finding.',
                ],
                true,
            ),
            'unknown' => $identity->kind === 'unknown'
                ? new RemediationAction(
                    $actionId,
                    $subjectId,
                    $identity->label,
                    $cve,
                    $advisoryTitle,
                    RemediationActionKind::InvestigateUnknownSubject,
                    sprintf('%s (%s): no runtime subject could be correlated to this assessment, so applicability cannot be determined. %s', $advisoryTitle, $cve, $safeRationale),
                    $validEvidenceIds,
                    [],
                    'Manually verify which PHP runtime(s) serve this host and re-run the audit tool with appropriate access.',
                    'None; no change is proposed.',
                    'Not applicable.',
                    'Re-run the inventory collector and confirm at least one runtime or worker subject is discovered for this host.',
                    ['Which PHP runtime, if any, actually serves this host.', sprintf('Whether this host is affected by %s at all.', $cve)],
                    false,
                )
                : new RemediationAction(
                    $actionId,
                    $subjectId,
                    $identity->label,
                    $cve,
                    $advisoryTitle,
                    RemediationActionKind::AwaitVendorEvidence,
                    sprintf('%s (%s): vendor or package provenance evidence is insufficient to determine patch status for this subject. %s', $advisoryTitle, $cve, $safeRationale),
                    $validEvidenceIds,
                    [
                        'Identify the exact OS distribution and release serving this subject.',
                        'Confirm whether your vendor backports security fixes independently of upstream version numbers.',
                    ],
                    'Do not assume this subject is vulnerable or fixed. Monitor official vendor and distribution security advisories for this package, and re-run the audit once new vendor evidence is available.' . $sourceNote,
                    'Treating an unknown verdict as safe could leave a real vulnerability unaddressed; treating it as vulnerable could cause an unnecessary, potentially disruptive change.',
                    'Not applicable (no change proposed).',
                    'Re-run the audit after vendor provenance evidence becomes available and confirm the verdict updates accordingly.',
                    [
                        'Vendor backport status for this exact package or version.',
                        'Whether the running worker binary matches any package evidence that does exist.',
                    ],
                    false,
                ),
            default => $this->recordUnsupportedVerdict($warnings, $cve),
        };
    }

    /**
     * @param array<string, ReportFact> $factsById
     * @param array<string, ReportFact> $factsByKey
     * @return list<string>
     */
    private function configurationEvidenceIds(string $cve, string $subjectId, array $factsById, array $factsByKey): array
    {
        $basis = $factsByKey['advisory.' . $cve . '.' . $subjectId . '.assessment_basis'] ?? null;
        $basisValue = $basis['value'] ?? null;
        if ($basisValue instanceof \stdClass) {
            $basisValue = get_object_vars($basisValue);
        }
        $configurationFactIds = is_array($basisValue) ? ($basisValue['configuration_fact_ids'] ?? null) : null;
        if (!is_array($configurationFactIds) || !array_is_list($configurationFactIds)) {
            return [];
        }

        $evidenceIds = [];
        foreach ($configurationFactIds as $factId) {
            if (!is_string($factId)) {
                continue;
            }
            $fact = $factsById[$factId] ?? null;
            if ($fact !== null && str_starts_with($fact['key'], 'configuration.')) {
                $evidenceIds[] = $factId;
            }
        }

        return array_values(array_unique($evidenceIds));
    }

    /** @param list<string> $warnings */
    private function recordUnsupportedVerdict(array &$warnings, string $cve): null
    {
        $warnings[] = sprintf('%s has an unsupported verdict value and was skipped.', $cve);

        return null;
    }
}
