<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

final readonly class ValidationResult
{
    /** @param list<string> $errors */
    public function __construct(
        public bool $valid,
        public ?RecordType $recordType,
        public ?string $schemaVersion,
        public array $errors,
        public ?EvidenceRecord $record = null,
    ) {}

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'valid' => $this->valid,
            'record_type' => $this->recordType?->value,
            'schema_version' => $this->schemaVersion,
            'errors' => $this->errors,
        ];
    }
}
