<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

final readonly class ObservationFact
{
    private function __construct(
        public string $factId,
        public string $key,
        public mixed $value,
        public string $sourceId,
    ) {}

    /**
     * @internal Call only after the observation schema has validated this record.
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        RecordData::rejectUnknownKeys($data, ['fact_id', 'key', 'value', 'source_id'], 'observation fact');
        if (!array_key_exists('value', $data)) {
            throw new \InvalidArgumentException('Observation fact is missing its value field.');
        }

        return new self(
            factId: RecordData::string($data, 'fact_id'),
            key: RecordData::string($data, 'key'),
            value: $data['value'],
            sourceId: RecordData::string($data, 'source_id'),
        );
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'fact_id' => $this->factId,
            'key' => $this->key,
            'value' => $this->value,
            'source_id' => $this->sourceId,
        ];
    }
}
