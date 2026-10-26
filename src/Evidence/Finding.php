<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

use InvalidArgumentException;

final readonly class Finding implements EvidenceRecord
{
    /** @param list<string> $evidenceIds */
    private function __construct(
        public string $findingId,
        public string $schemaVersion,
        public string $subjectId,
        public string $createdAt,
        public FindingStatus $status,
        public FindingKind $kind,
        public bool $material,
        public string $title,
        public ?string $observedImpact,
        public array $evidenceIds,
        public ?IndependentVerification $independentVerification,
    ) {}

    /**
     * @internal Call only after the finding schema has validated this record.
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        RecordData::rejectUnknownKeys($data, [
            'record_type', 'schema_version', 'finding_id', 'subject_id', 'created_at', 'status', 'kind',
            'material', 'title', 'observed_impact', 'evidence_ids', 'independent_verification',
        ], 'finding');
        if (($data['record_type'] ?? null) !== RecordType::Finding->value || ($data['schema_version'] ?? null) !== '1.0') {
            throw new InvalidArgumentException('Unsupported finding record type or schema version.');
        }

        $status = FindingStatus::tryFrom(RecordData::string($data, 'status'));
        $kind = FindingKind::tryFrom(RecordData::string($data, 'kind'));
        if ($status === null || $kind === null) {
            throw new InvalidArgumentException('Unsupported finding status or kind.');
        }
        $material = $data['material'] ?? null;
        if (!is_bool($material)) {
            throw new InvalidArgumentException('material must be a boolean.');
        }
        $observedImpact = $data['observed_impact'] ?? null;
        if ($observedImpact !== null && !is_string($observedImpact)) {
            throw new InvalidArgumentException('observed_impact must be a string or null.');
        }
        $evidenceIds = RecordData::stringList($data, 'evidence_ids');
        if ($evidenceIds === []) {
            throw new InvalidArgumentException('A finding requires evidence_ids.');
        }
        $verificationData = $data['independent_verification'] ?? null;
        $verification = $verificationData === null
            ? null
            : IndependentVerification::fromArray(RecordData::object($verificationData, 'independent_verification'));

        if ($status === FindingStatus::Confirmed && $material && $verification === null) {
            throw new InvalidArgumentException('Material confirmed findings require independent_verification.');
        }
        if ($verification !== null && array_intersect($evidenceIds, $verification->evidenceIds) !== []) {
            throw new InvalidArgumentException('Independent verification must cite evidence distinct from the finding evidence.');
        }

        return new self(
            findingId: RecordData::string($data, 'finding_id'),
            schemaVersion: '1.0',
            subjectId: RecordData::string($data, 'subject_id'),
            createdAt: RecordData::timestamp(RecordData::string($data, 'created_at'), 'created_at'),
            status: $status,
            kind: $kind,
            material: $material,
            title: RecordData::string($data, 'title'),
            observedImpact: $observedImpact,
            evidenceIds: $evidenceIds,
            independentVerification: $verification,
        );
    }

    public function recordType(): RecordType
    {
        return RecordType::Finding;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'record_type' => $this->recordType()->value,
            'schema_version' => $this->schemaVersion,
            'finding_id' => $this->findingId,
            'subject_id' => $this->subjectId,
            'created_at' => $this->createdAt,
            'status' => $this->status->value,
            'kind' => $this->kind->value,
            'material' => $this->material,
            'title' => $this->title,
            'observed_impact' => $this->observedImpact,
            'evidence_ids' => $this->evidenceIds,
            'independent_verification' => $this->independentVerification?->toArray(),
        ];
    }
}
