<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

use InvalidArgumentException;

final readonly class Coverage implements EvidenceRecord
{
    /** @param list<CoverageEntry> $entries */
    private function __construct(
        public string $recordId,
        public string $schemaVersion,
        public string $recordedAt,
        public array $entries,
    ) {}

    /**
     * @internal Call only after the coverage schema has validated this record.
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        RecordData::rejectUnknownKeys($data, ['record_type', 'schema_version', 'record_id', 'recorded_at', 'entries'], 'coverage');
        if (($data['record_type'] ?? null) !== RecordType::Coverage->value || ($data['schema_version'] ?? null) !== '1.0') {
            throw new InvalidArgumentException('Unsupported coverage record type or schema version.');
        }

        $entries = array_map(
            static fn(array $entry): CoverageEntry => CoverageEntry::fromArray($entry),
            RecordData::objectList($data['entries'] ?? null, 'entries'),
        );
        $keys = [];
        foreach ($entries as $entry) {
            $key = $entry->subjectId . "\0" . $entry->checkId;
            if (isset($keys[$key])) {
                throw new InvalidArgumentException('Coverage contains duplicate subject_id/check_id pairs.');
            }
            $keys[$key] = true;
        }

        return new self(
            recordId: RecordData::string($data, 'record_id'),
            schemaVersion: '1.0',
            recordedAt: RecordData::timestamp(RecordData::string($data, 'recorded_at'), 'recorded_at'),
            entries: $entries,
        );
    }

    public function recordType(): RecordType
    {
        return RecordType::Coverage;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'record_type' => $this->recordType()->value,
            'schema_version' => $this->schemaVersion,
            'record_id' => $this->recordId,
            'recorded_at' => $this->recordedAt,
            'entries' => array_map(static fn(CoverageEntry $entry): array => $entry->toArray(), $this->entries),
        ];
    }
}
