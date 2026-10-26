<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

use InvalidArgumentException;

final readonly class CompromiseEvidence
{
    /** @param list<string> $evidenceIds */
    private function __construct(
        public CompromiseStatus $status,
        public array $evidenceIds,
    ) {}

    /**
     * @internal Call only after the assessment schema has validated this record.
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        RecordData::rejectUnknownKeys($data, ['status', 'evidence_ids'], 'compromise_evidence');
        $status = CompromiseStatus::tryFrom(RecordData::string($data, 'status'));
        if ($status === null) {
            throw new InvalidArgumentException('Unsupported compromise evidence status.');
        }
        $evidenceIds = RecordData::stringList($data, 'evidence_ids');
        if (in_array($status, [CompromiseStatus::Suspected, CompromiseStatus::Confirmed], true) && $evidenceIds === []) {
            throw new InvalidArgumentException('Suspected or confirmed compromise requires evidence_ids.');
        }

        return new self($status, $evidenceIds);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return ['status' => $this->status->value, 'evidence_ids' => $this->evidenceIds];
    }
}
