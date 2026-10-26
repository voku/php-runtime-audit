<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

use InvalidArgumentException;
use JsonException;
use stdClass;

/** @internal Hydrates records after schema validation; use EvidenceValidator for untrusted JSON. */
final class EvidenceModelFactory
{
    /** @internal The object must already have passed its versioned JSON Schema. */
    public static function fromObject(stdClass $data, RecordType $type): EvidenceRecord
    {
        $values = RecordData::object($data, 'evidence record');

        return match ($type) {
            RecordType::Observation => Observation::fromArray($values),
            RecordType::Applicability => ApplicabilityRecord::fromArray($values),
            RecordType::Assessment => Assessment::fromArray($values),
            RecordType::Coverage => Coverage::fromArray($values),
            RecordType::Finding => Finding::fromArray($values),
        };
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): EvidenceRecord
    {
        try {
            $json = json_encode($data, JSON_THROW_ON_ERROR);
        } catch (JsonException $error) {
            throw new InvalidArgumentException('Evidence array cannot be encoded as JSON.', 0, $error);
        }

        $result = (new EvidenceValidator())->validate($json);
        if (!$result->valid || $result->record === null) {
            throw new InvalidArgumentException('Evidence array failed schema validation: ' . implode('; ', $result->errors));
        }

        return $result->record;
    }
}
