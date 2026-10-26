<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

use InvalidArgumentException;

final readonly class CoverageEntry
{
    /** @param list<string> $evidenceIds */
    private function __construct(
        public string $subjectId,
        public string $checkId,
        public CoverageStatus $status,
        public array $evidenceIds,
        public ?string $gap,
    ) {}

    /**
     * @internal Call only after the coverage schema has validated this record.
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        RecordData::rejectUnknownKeys($data, ['subject_id', 'check_id', 'status', 'evidence_ids', 'gap'], 'coverage entry');
        $status = CoverageStatus::tryFrom(RecordData::string($data, 'status'));
        if ($status === null) {
            throw new InvalidArgumentException('Unsupported coverage status.');
        }
        $evidenceIds = RecordData::stringList($data, 'evidence_ids');
        $gap = $data['gap'] ?? null;
        if ($gap !== null && !is_string($gap)) {
            throw new InvalidArgumentException('gap must be a string or null.');
        }
        if ($status !== CoverageStatus::Attempted && ($gap === null || trim($gap) === '')) {
            throw new InvalidArgumentException('Skipped or blocked coverage requires a precise gap.');
        }
        if ($status === CoverageStatus::Attempted && $evidenceIds === [] && ($gap === null || trim($gap) === '')) {
            throw new InvalidArgumentException('Attempted coverage without evidence requires a gap.');
        }

        return new self(
            subjectId: RecordData::string($data, 'subject_id'),
            checkId: RecordData::string($data, 'check_id'),
            status: $status,
            evidenceIds: $evidenceIds,
            gap: $gap,
        );
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'subject_id' => $this->subjectId,
            'check_id' => $this->checkId,
            'status' => $this->status->value,
            'evidence_ids' => $this->evidenceIds,
            'gap' => $this->gap,
        ];
    }
}
