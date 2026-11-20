<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Advisories;

use RuntimeException;
use voku\PhpRuntimeAudit\Evidence\EvidenceValidator;
use voku\PhpRuntimeAudit\Evidence\RecordType;
use voku\PhpRuntimeAudit\RuntimeInventory\RuntimeInventoryCollector;

/**
 * Builds and schema-validates local evidence records before output.
 *
 * @phpstan-import-type RuntimeInventory from RuntimeInventoryCollector
 * @phpstan-import-type AdvisoryEvaluation from AdvisoryEvaluator
 * @phpstan-import-type AdvisoryAssessment from AdvisoryEvaluator
 * @phpstan-import-type RuntimeCoverage from RuntimeInventoryCollector
 * @phpstan-type RuntimeAuditReport array{report_schema_version: '1.0', summary: array{observed_at: string, distribution: string|null, distribution_version: string|null, container: bool|null, web_worker_count: int, coverage_count: int, assessment_count: int, omitted_subject_count: int, verdict_counts: array<string, int>, compromise_evidence: 'unknown'}, records: list<array<string, mixed>>}
 */
final readonly class RuntimeAuditReportBuilder
{
    public function __construct(private EvidenceValidator $validator = new EvidenceValidator()) {}

    /**
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-param AdvisoryEvaluation $evaluation
     * @phpstan-return RuntimeAuditReport
     */
    public function build(array $inventory, array $evaluation): array
    {
        $sourcesById = [];
        foreach (array_merge($inventory['sources'], $evaluation['sources']) as $source) {
            $sourcesById[$source['source_id']] = $source;
        }
        $facts = array_merge($inventory['facts'], $evaluation['facts']);
        $assessments = $evaluation['assessments'];
        if (count($sourcesById) > AdvisoryEvaluator::MAX_REPORT_SOURCES || count($facts) > AdvisoryEvaluator::MAX_REPORT_FACTS || count($assessments) > AdvisoryEvaluator::MAX_ASSESSMENTS) {
            // The evaluator keeps assessments within the limits; what remains is evidence that is
            // always emitted. Name both parts so an oversized inventory is recognisable as such.
            throw new RuntimeException(sprintf(
                'Generated local evidence exceeds schema collection limits: inventory evidence (%d facts, %d sources) plus advisory evidence (%d facts, %d sources, %d assessments) exceeds %d facts, %d sources or %d assessments.',
                count($inventory['facts']),
                count($inventory['sources']),
                count($evaluation['facts']),
                count($evaluation['sources']),
                count($assessments),
                AdvisoryEvaluator::MAX_REPORT_FACTS,
                AdvisoryEvaluator::MAX_REPORT_SOURCES,
                AdvisoryEvaluator::MAX_ASSESSMENTS,
            ));
        }

        $timestamp = strtotime($inventory['observed_at']);
        $observation = [
            'record_type' => 'observation',
            'schema_version' => '1.0',
            'observation_id' => 'observation.runtime-inventory.'
                . gmdate('YmdHis', $timestamp === false ? 0 : $timestamp)
                . '.' . bin2hex(random_bytes(6)),
            'collector_id' => 'php-runtime-audit.local-inventory',
            'asset_id' => $inventory['asset_id'],
            'observed_at' => $inventory['observed_at'],
            'redaction_status' => 'complete',
            'sources' => array_values($sourcesById),
            'facts' => $facts,
        ];

        $records = [$this->validateRecord($observation, RecordType::Observation)];
        $coverageEntries = [];
        foreach ($inventory['coverage'] as $entry) {
            $coverageEntries[] = [
                'subject_id' => $inventory['asset_id'],
                'check_id' => $entry['check_id'],
                'status' => $entry['status'],
                'evidence_ids' => array_values(array_unique($entry['evidence_ids'])),
                'gap' => $entry['gap'],
            ];
        }
        $omitted = $evaluation['omitted_subject_ids'] ?? [];
        if ($omitted !== []) {
            // Never imply full coverage: subjects beyond the assessment budget are reported as not assessed.
            $listed = implode(', ', array_slice($omitted, 0, 12)) . (count($omitted) > 12 ? ', ...' : '');
            $gap = sprintf(
                'The report budget (%d assessments, one per advisory and runtime subject, within the %d-fact, %d-source and 1 MiB evidence limits) was reached, so %d runtime subject(s) were not assessed. Running web workers were assessed first, then CLI runtimes, then packages, then further identical workers of an already assessed runtime. Not assessed: %s.',
                AdvisoryEvaluator::MAX_ASSESSMENTS,
                AdvisoryEvaluator::MAX_REPORT_FACTS,
                AdvisoryEvaluator::MAX_REPORT_SOURCES,
                count($omitted),
                $listed,
            );
            $coverageEntries[] = [
                'subject_id' => $inventory['asset_id'],
                'check_id' => 'advisory.assessment-budget',
                'status' => 'blocked',
                'evidence_ids' => [],
                'gap' => strlen($gap) > 1000 ? substr($gap, 0, 997) . '...' : $gap,
            ];
        }
        $coverageRecord = [
            'record_type' => 'coverage',
            'schema_version' => '1.0',
            'record_id' => 'coverage.runtime-inventory.'
                . gmdate('YmdHis', $timestamp === false ? 0 : $timestamp)
                . '.' . bin2hex(random_bytes(6)),
            'recorded_at' => $inventory['observed_at'],
            'entries' => $coverageEntries,
        ];
        $records[] = $this->validateRecord($coverageRecord, RecordType::Coverage);
        foreach ($assessments as $assessment) {
            $records[] = $this->validateRecord($assessment, RecordType::Assessment);
        }
        $summary = [
            'observed_at' => $observation['observed_at'],
            'distribution' => $inventory['distribution'],
            'distribution_version' => $inventory['distribution_version'],
            'container' => $inventory['container'],
            'web_worker_count' => count($inventory['workers']),
            'coverage_count' => count($coverageEntries),
            'assessment_count' => count($assessments),
            'omitted_subject_count' => count($omitted),
            'verdict_counts' => $this->verdictCounts($assessments),
            'compromise_evidence' => 'unknown',
        ];
        $report = ['report_schema_version' => '1.0', 'summary' => $summary, 'records' => $records];
        $json = json_encode($report, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (strlen($json) > EvidenceValidator::MAX_INPUT_BYTES) {
            throw new RuntimeException('Generated report exceeds the 1 MiB output limit.');
        }

        return $report;
    }

    /**
     * @param array<string, mixed> $record
     * @return array<string, mixed>
     */
    private function validateRecord(array $record, RecordType $expectedType): array
    {
        $json = json_encode($record, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $result = $this->validator->validate($json);
        if (!$result->valid || $result->recordType !== $expectedType || $result->record === null) {
            throw new RuntimeException('Generated evidence failed schema validation: ' . implode(' ', $result->errors));
        }

        return $result->record->toArray();
    }

    /**
     * @phpstan-param list<AdvisoryAssessment> $assessments
     * @phpstan-return array<string, int>
     */
    private function verdictCounts(array $assessments): array
    {
        $counts = ['verified_fixed' => 0, 'potentially_affected' => 0, 'unknown' => 0, 'needs_investigation' => 0];
        foreach ($assessments as $assessment) {
            $verdict = $assessment['verdict'];
            if (!array_key_exists($verdict, $counts)) {
                continue;
            }
            ++$counts[$verdict];
        }

        return $counts;
    }
}
