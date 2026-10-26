<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

use InvalidArgumentException;

final readonly class ApplicabilityRecord implements EvidenceRecord
{
    /** @param list<string> $evidenceIds */
    private function __construct(
        public string $recordId,
        public string $schemaVersion,
        public string $subjectId,
        public string $checkId,
        public string $assessedAt,
        public ApplicabilityState $state,
        public array $evidenceIds,
        public ?string $reason,
    ) {}

    /**
     * @internal Call only after the applicability schema has validated this record.
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        RecordData::rejectUnknownKeys($data, [
            'record_type', 'schema_version', 'record_id', 'subject_id', 'check_id', 'assessed_at', 'state',
            'evidence_ids', 'reason',
        ], 'applicability');
        self::assertEnvelope($data, RecordType::Applicability);

        $state = ApplicabilityState::tryFrom(RecordData::string($data, 'state'));
        if ($state === null) {
            throw new InvalidArgumentException('Unsupported applicability state.');
        }
        $evidenceIds = RecordData::stringList($data, 'evidence_ids');
        $reason = $data['reason'] ?? null;
        if ($reason !== null && !is_string($reason)) {
            throw new InvalidArgumentException('reason must be a string or null.');
        }
        if ($state === ApplicabilityState::Unknown && ($reason === null || trim($reason) === '')) {
            throw new InvalidArgumentException('Unknown applicability requires a reason.');
        }
        if ($state !== ApplicabilityState::Unknown && $evidenceIds === []) {
            throw new InvalidArgumentException('Known applicability requires evidence_ids.');
        }

        return new self(
            recordId: RecordData::string($data, 'record_id'),
            schemaVersion: '1.0',
            subjectId: RecordData::string($data, 'subject_id'),
            checkId: RecordData::string($data, 'check_id'),
            assessedAt: RecordData::timestamp(RecordData::string($data, 'assessed_at'), 'assessed_at'),
            state: $state,
            evidenceIds: $evidenceIds,
            reason: $reason,
        );
    }

    public function recordType(): RecordType
    {
        return RecordType::Applicability;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'record_type' => $this->recordType()->value,
            'schema_version' => $this->schemaVersion,
            'record_id' => $this->recordId,
            'subject_id' => $this->subjectId,
            'check_id' => $this->checkId,
            'assessed_at' => $this->assessedAt,
            'state' => $this->state->value,
            'evidence_ids' => $this->evidenceIds,
            'reason' => $this->reason,
        ];
    }

    /** @param array<string, mixed> $data */
    private static function assertEnvelope(array $data, RecordType $type): void
    {
        if (($data['record_type'] ?? null) !== $type->value || ($data['schema_version'] ?? null) !== '1.0') {
            throw new InvalidArgumentException('Unsupported record type or schema version.');
        }
    }
}
