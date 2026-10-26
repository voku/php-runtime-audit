<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

final readonly class IndependentVerification
{
    /** @param list<string> $evidenceIds */
    private function __construct(
        public string $verifierId,
        public string $verifiedAt,
        public string $method,
        public array $evidenceIds,
    ) {}

    /**
     * @internal Call only after the finding schema has validated this record.
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        RecordData::rejectUnknownKeys($data, ['verifier_id', 'verified_at', 'method', 'evidence_ids'], 'independent_verification');

        return new self(
            verifierId: RecordData::string($data, 'verifier_id'),
            verifiedAt: RecordData::timestamp(RecordData::string($data, 'verified_at'), 'verified_at'),
            method: RecordData::string($data, 'method'),
            evidenceIds: RecordData::stringList($data, 'evidence_ids'),
        );
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'verifier_id' => $this->verifierId,
            'verified_at' => $this->verifiedAt,
            'method' => $this->method,
            'evidence_ids' => $this->evidenceIds,
        ];
    }
}
