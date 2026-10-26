<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

use InvalidArgumentException;

final readonly class Observation implements EvidenceRecord
{
    /**
     * @param list<SourceReference> $sources
     * @param list<ObservationFact> $facts
     */
    private function __construct(
        public string $observationId,
        public string $schemaVersion,
        public string $collectorId,
        public string $assetId,
        public string $observedAt,
        public RedactionStatus $redactionStatus,
        public array $sources,
        public array $facts,
    ) {}

    /**
     * @internal Call only after the observation schema has validated this record.
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        RecordData::rejectUnknownKeys($data, [
            'record_type', 'schema_version', 'observation_id', 'collector_id', 'asset_id', 'observed_at',
            'redaction_status', 'sources', 'facts',
        ], 'observation');

        if (($data['record_type'] ?? null) !== RecordType::Observation->value || ($data['schema_version'] ?? null) !== '1.0') {
            throw new InvalidArgumentException('Unsupported observation record type or schema version.');
        }

        $redaction = RedactionStatus::tryFrom(RecordData::string($data, 'redaction_status'));
        if ($redaction === null) {
            throw new InvalidArgumentException('Unsupported redaction_status value.');
        }

        $sources = array_map(
            static fn(array $source): SourceReference => SourceReference::fromArray($source),
            RecordData::objectList($data['sources'] ?? null, 'sources'),
        );
        $facts = array_map(
            static fn(array $fact): ObservationFact => ObservationFact::fromArray($fact),
            RecordData::objectList($data['facts'] ?? null, 'facts'),
        );

        $sourceIds = array_map(static fn(SourceReference $source): string => $source->sourceId, $sources);
        self::assertUnique($sourceIds, 'source_id');
        $factIds = array_map(static fn(ObservationFact $fact): string => $fact->factId, $facts);
        self::assertUnique($factIds, 'fact_id');
        foreach ($facts as $fact) {
            if (!in_array($fact->sourceId, $sourceIds, true)) {
                throw new InvalidArgumentException('An observation fact refers to a missing source_id.');
            }
        }

        return new self(
            observationId: RecordData::string($data, 'observation_id'),
            schemaVersion: '1.0',
            collectorId: RecordData::string($data, 'collector_id'),
            assetId: RecordData::string($data, 'asset_id'),
            observedAt: RecordData::timestamp(RecordData::string($data, 'observed_at'), 'observed_at'),
            redactionStatus: $redaction,
            sources: $sources,
            facts: $facts,
        );
    }

    public function recordType(): RecordType
    {
        return RecordType::Observation;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'record_type' => $this->recordType()->value,
            'schema_version' => $this->schemaVersion,
            'observation_id' => $this->observationId,
            'collector_id' => $this->collectorId,
            'asset_id' => $this->assetId,
            'observed_at' => $this->observedAt,
            'redaction_status' => $this->redactionStatus->value,
            'sources' => array_map(static fn(SourceReference $source): array => $source->toArray(), $this->sources),
            'facts' => array_map(static fn(ObservationFact $fact): array => $fact->toArray(), $this->facts),
        ];
    }

    /** @param list<string> $values */
    private static function assertUnique(array $values, string $field): void
    {
        if (count($values) !== count(array_unique($values))) {
            throw new InvalidArgumentException(sprintf('Observation contains duplicate %s values.', $field));
        }
    }
}
