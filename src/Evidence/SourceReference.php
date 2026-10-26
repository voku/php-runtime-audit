<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

use InvalidArgumentException;

final readonly class SourceReference
{
    private function __construct(
        public string $sourceId,
        public string $kind,
        public string $locator,
        public string $capturedAt,
        public ?string $capturedDigest,
        public ?string $currentDigest,
        public Freshness $freshness,
    ) {}

    /**
     * @internal Call only after the observation schema has validated this record.
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        RecordData::rejectUnknownKeys($data, [
            'source_id', 'kind', 'locator', 'captured_at', 'captured_digest', 'current_digest', 'freshness',
        ], 'source reference');

        $capturedDigest = self::digest($data['captured_digest'] ?? null, 'captured_digest');
        $currentDigest = self::digest($data['current_digest'] ?? null, 'current_digest');
        $freshness = Freshness::fromDigests($capturedDigest, $currentDigest);
        if (($data['freshness'] ?? null) !== $freshness->value) {
            throw new InvalidArgumentException('Source-reference freshness does not match the supplied digests.');
        }

        return new self(
            sourceId: RecordData::string($data, 'source_id'),
            kind: RecordData::string($data, 'kind'),
            locator: RecordData::string($data, 'locator'),
            capturedAt: RecordData::timestamp(RecordData::string($data, 'captured_at'), 'captured_at'),
            capturedDigest: $capturedDigest,
            currentDigest: $currentDigest,
            freshness: $freshness,
        );
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'source_id' => $this->sourceId,
            'kind' => $this->kind,
            'locator' => $this->locator,
            'captured_at' => $this->capturedAt,
            'captured_digest' => $this->capturedDigest,
            'current_digest' => $this->currentDigest,
            'freshness' => $this->freshness->value,
        ];
    }

    private static function digest(mixed $value, string $field): ?string
    {
        if ($value === null) {
            return null;
        }

        if (!is_string($value) || preg_match('/\Asha256:[a-f0-9]{64}\z/', $value) !== 1) {
            throw new InvalidArgumentException(sprintf('%s must be a lowercase sha256 digest or null.', $field));
        }

        return $value;
    }
}
