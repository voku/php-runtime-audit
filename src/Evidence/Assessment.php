<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

use InvalidArgumentException;

final readonly class Assessment implements EvidenceRecord
{
    /** @param list<string> $patchEvidenceIds */
    private function __construct(
        public string $recordId,
        public string $schemaVersion,
        public string $subjectId,
        public string $assessedAt,
        public AssessmentVerdict $verdict,
        public PatchStatus $patchStatus,
        public array $patchEvidenceIds,
        public CompromiseEvidence $compromiseEvidence,
        public string $rationale,
    ) {}

    /**
     * @internal Call only after the assessment schema has validated this record.
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        RecordData::rejectUnknownKeys($data, [
            'record_type', 'schema_version', 'record_id', 'subject_id', 'assessed_at', 'verdict', 'patch_status',
            'patch_evidence_ids', 'compromise_evidence', 'rationale',
        ], 'assessment');
        if (($data['record_type'] ?? null) !== RecordType::Assessment->value || ($data['schema_version'] ?? null) !== '1.0') {
            throw new InvalidArgumentException('Unsupported assessment record type or schema version.');
        }

        $verdict = AssessmentVerdict::tryFrom(RecordData::string($data, 'verdict'));
        $patchStatus = PatchStatus::tryFrom(RecordData::string($data, 'patch_status'));
        if ($verdict === null || $patchStatus === null) {
            throw new InvalidArgumentException('Unsupported assessment verdict or patch_status.');
        }
        $patchEvidenceIds = RecordData::stringList($data, 'patch_evidence_ids');
        $compromise = CompromiseEvidence::fromArray(RecordData::object($data['compromise_evidence'] ?? null, 'compromise_evidence'));
        $rationale = RecordData::string($data, 'rationale');

        if ($patchStatus === PatchStatus::VerifiedFixed && $patchEvidenceIds === []) {
            throw new InvalidArgumentException('verified_fixed patch_status requires patch evidence.');
        }
        if ($patchStatus === PatchStatus::PotentiallyAffected && $patchEvidenceIds === []) {
            throw new InvalidArgumentException('potentially_affected patch_status requires patch evidence.');
        }
        if ($verdict === AssessmentVerdict::VerifiedFixed && $patchStatus !== PatchStatus::VerifiedFixed) {
            throw new InvalidArgumentException('verified_fixed verdict requires matching patch_status.');
        }
        if ($verdict === AssessmentVerdict::PotentiallyAffected && $patchStatus !== PatchStatus::PotentiallyAffected) {
            throw new InvalidArgumentException('potentially_affected requires matching patch_status.');
        }
        if ($verdict === AssessmentVerdict::Unknown && $patchStatus !== PatchStatus::Unknown) {
            throw new InvalidArgumentException('unknown requires patch_status unknown.');
        }

        return new self(
            recordId: RecordData::string($data, 'record_id'),
            schemaVersion: '1.0',
            subjectId: RecordData::string($data, 'subject_id'),
            assessedAt: RecordData::timestamp(RecordData::string($data, 'assessed_at'), 'assessed_at'),
            verdict: $verdict,
            patchStatus: $patchStatus,
            patchEvidenceIds: $patchEvidenceIds,
            compromiseEvidence: $compromise,
            rationale: $rationale,
        );
    }

    public function recordType(): RecordType
    {
        return RecordType::Assessment;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'record_type' => $this->recordType()->value,
            'schema_version' => $this->schemaVersion,
            'record_id' => $this->recordId,
            'subject_id' => $this->subjectId,
            'assessed_at' => $this->assessedAt,
            'verdict' => $this->verdict->value,
            'patch_status' => $this->patchStatus->value,
            'patch_evidence_ids' => $this->patchEvidenceIds,
            'compromise_evidence' => $this->compromiseEvidence->toArray(),
            'rationale' => $this->rationale,
        ];
    }
}
