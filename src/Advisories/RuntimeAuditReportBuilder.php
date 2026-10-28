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
 * @phpstan-type ReportSource array{source_id: string, kind: string, locator: string, captured_at: string, captured_digest: string|null, current_digest: string|null, freshness: string}
 * @phpstan-type ReportFact array{fact_id: string, key: string, value: mixed, source_id: string}
 * @phpstan-type ObservationChunk array{sources: list<ReportSource>, facts: list<ReportFact>}
 * @phpstan-type RuntimeAuditReport array{report_schema_version: '1.0', summary: array{observed_at: string, distribution: string|null, distribution_version: string|null, container: bool|null, web_worker_count: int, coverage_count: int, assessment_count: int, verdict_counts: array<string, int>, compromise_evidence: 'unknown'}, records: list<array<string, mixed>>}
 */
final readonly class RuntimeAuditReportBuilder
{
    private const MAX_SOURCES_PER_OBSERVATION = 256;
    private const MAX_FACTS_PER_OBSERVATION = 1024;
    public const MAX_REPORT_RECORDS = 16_384;
    public const MAX_REPORT_FACTS = 32_768;
    private const MAX_ASSESSMENTS = 8192;
    // The bounded catalog and target limits can produce thousands of individually validated records.
    public const MAX_REPORT_BYTES = 64 * 1024 * 1024;

    public function __construct(private EvidenceValidator $validator = new EvidenceValidator()) {}

    /**
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-param AdvisoryEvaluation $evaluation
     * @phpstan-return RuntimeAuditReport
     */
    public function build(array $inventory, array $evaluation): array
    {
        /** @var array<string, ReportSource> $sourcesById */
        $sourcesById = [];
        foreach (array_merge($inventory['sources'], $evaluation['sources']) as $source) {
            $sourcesById[$source['source_id']] = $source;
        }
        /** @var list<ReportFact> $facts */
        $facts = array_merge($inventory['facts'], $evaluation['facts']);
        if (count($facts) > self::MAX_REPORT_FACTS) {
            throw new RuntimeException('Generated local evidence exceeds the bounded report fact limit.');
        }
        $assessments = $evaluation['assessments'];
        if (count($assessments) > self::MAX_ASSESSMENTS) {
            throw new RuntimeException('Generated local evidence exceeds the bounded assessment limit.');
        }

        $timestamp = strtotime($inventory['observed_at']);
        $records = [];
        foreach ($this->observationChunks($sourcesById, $facts) as $chunk) {
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
                'sources' => $chunk['sources'],
                'facts' => $chunk['facts'],
            ];
            $records[] = $this->validateRecord($observation, RecordType::Observation);
        }

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
        foreach ($evaluation['coverage'] as $entry) {
            $coverageEntries[] = [
                'subject_id' => $inventory['asset_id'],
                'check_id' => $entry['check_id'],
                'status' => $entry['status'],
                'evidence_ids' => array_values(array_unique($entry['evidence_ids'])),
                'gap' => $entry['gap'],
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
        if (count($records) > self::MAX_REPORT_RECORDS) {
            throw new RuntimeException('Generated local evidence exceeds the bounded report record limit.');
        }
        $summary = [
            'observed_at' => $inventory['observed_at'],
            'distribution' => $inventory['distribution'],
            'distribution_version' => $inventory['distribution_version'],
            'container' => $inventory['container'],
            'web_worker_count' => count($inventory['workers']),
            'coverage_count' => count($coverageEntries),
            'assessment_count' => count($assessments),
            'verdict_counts' => $this->verdictCounts($assessments),
            'compromise_evidence' => 'unknown',
        ];
        $report = ['report_schema_version' => '1.0', 'summary' => $summary, 'records' => $records];
        $json = json_encode($report, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (strlen($json) > self::MAX_REPORT_BYTES) {
            throw new RuntimeException(sprintf(
                'Generated report exceeds the %d MiB output limit.',
                intdiv(self::MAX_REPORT_BYTES, 1024 * 1024),
            ));
        }

        return $report;
    }

    /**
     * @phpstan-param array<string, ReportSource> $sourcesById
     * @phpstan-param list<ReportFact> $facts
     * @phpstan-return list<ObservationChunk>
     */
    private function observationChunks(array $sourcesById, array $facts): array
    {
        if ($facts === []) {
            throw new RuntimeException('Generated local evidence contains no facts.');
        }

        /** @var array<string, string> $sourceIdsByLocator */
        $sourceIdsByLocator = [];
        foreach ($sourcesById as $sourceId => $source) {
            $sourceIdsByLocator[$source['locator']] = $sourceId;
        }

        $chunks = [];
        $chunkFacts = [];
        /** @var array<string, ReportSource> $chunkSources */
        $chunkSources = [];
        /** @var array<string, true> $retainedSourceIds */
        $retainedSourceIds = [];
        foreach ($facts as $fact) {
            $factSourceIds = $this->sourceIdsForFact($fact, $sourceIdsByLocator, $sourcesById);
            if (count($factSourceIds) > self::MAX_SOURCES_PER_OBSERVATION) {
                throw new RuntimeException('Generated local evidence fact exceeds the bounded source limit.');
            }

            $newSourceIds = array_values(array_filter(
                $factSourceIds,
                static fn(string $sourceId): bool => !isset($chunkSources[$sourceId]),
            ));
            if (count($chunkFacts) >= self::MAX_FACTS_PER_OBSERVATION
                || count($chunkSources) + count($newSourceIds) > self::MAX_SOURCES_PER_OBSERVATION) {
                $chunks[] = ['sources' => array_values($chunkSources), 'facts' => $chunkFacts];
                $chunkFacts = [];
                $chunkSources = [];
            }

            $chunkFacts[] = $fact;
            foreach ($factSourceIds as $sourceId) {
                $chunkSources[$sourceId] = $sourcesById[$sourceId];
                $retainedSourceIds[$sourceId] = true;
            }
        }

        $chunks[] = ['sources' => array_values($chunkSources), 'facts' => $chunkFacts];

        foreach ($sourcesById as $sourceId => $source) {
            if (isset($retainedSourceIds[$sourceId])) {
                continue;
            }

            $placed = false;
            foreach ($chunks as &$chunk) {
                if (count($chunk['sources']) < self::MAX_SOURCES_PER_OBSERVATION) {
                    $chunk['sources'][] = $source;
                    $retainedSourceIds[$sourceId] = true;
                    $placed = true;
                    break;
                }
            }
            unset($chunk);

            if (!$placed) {
                throw new RuntimeException('Generated local evidence sources exceed the bounded report capacity.');
            }
        }

        return $chunks;
    }

    /**
     * @param ReportFact $fact
     * @param array<string, string> $sourceIdsByLocator
     * @param array<string, ReportSource> $sourcesById
     * @return list<string>
     */
    private function sourceIdsForFact(array $fact, array $sourceIdsByLocator, array $sourcesById): array
    {
        $sourceIds = [$fact['source_id']];
        $pendingValues = [$fact['value']];
        while ($pendingValues !== []) {
            $value = array_pop($pendingValues);
            if (!is_array($value)) {
                continue;
            }

            foreach ($value as $key => $nested) {
                if ($key === 'evidence_source_ids' && is_array($nested)) {
                    foreach ($nested as $sourceId) {
                        if (is_string($sourceId)) {
                            $sourceIds[] = $sourceId;
                        }
                    }
                    continue;
                }

                if ($key === 'source_id' && is_string($nested)) {
                    $sourceIds[] = $nested;
                    continue;
                }

                if ($key === 'file' && is_string($nested)) {
                    if (isset($sourceIdsByLocator[$nested])) {
                        $sourceIds[] = $sourceIdsByLocator[$nested];
                    }
                    continue;
                }

                if ($key === 'files') {
                    $files = is_string($nested) ? [$nested] : $nested;
                    if (is_array($files)) {
                        foreach ($files as $file) {
                            if (is_string($file) && isset($sourceIdsByLocator[$file])) {
                                $sourceIds[] = $sourceIdsByLocator[$file];
                            }
                        }
                    }
                    continue;
                }

                if (is_array($nested)) {
                    $pendingValues[] = $nested;
                }
            }
        }

        $sourceIds = array_values(array_unique($sourceIds));
        foreach ($sourceIds as $sourceId) {
            if (!isset($sourcesById[$sourceId])) {
                throw new RuntimeException('Generated local evidence refers to an unknown fact source.');
            }
        }

        return $sourceIds;
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
