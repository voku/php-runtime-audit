<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

use Opis\JsonSchema\Errors\ValidationError;
use Opis\JsonSchema\Validator;
use stdClass;
use Throwable;

final class EvidenceValidator
{
    public const MAX_INPUT_BYTES = 1_048_576;
    private const SCHEMA_VERSION = '1.0';

    public function validate(string $json): ValidationResult
    {
        if (strlen($json) > self::MAX_INPUT_BYTES) {
            return new ValidationResult(false, null, null, ['Input exceeds the 1 MiB size limit.']);
        }

        try {
            DuplicateJsonKeyGuard::assertNoDuplicates($json);
            $data = json_decode($json, false, 64, JSON_THROW_ON_ERROR);
        } catch (Throwable $error) {
            return new ValidationResult(false, null, null, [$this->safeError($error)]);
        }

        if (!$data instanceof stdClass) {
            return new ValidationResult(false, null, null, ['Evidence record must be a JSON object.']);
        }

        $typeValue = $data->record_type ?? null;
        $version = $data->schema_version ?? null;
        $type = is_string($typeValue) ? RecordType::tryFrom($typeValue) : null;
        if ($type === null) {
            return new ValidationResult(false, null, is_string($version) ? $version : null, ['Unknown or missing record_type.']);
        }
        if ($version !== self::SCHEMA_VERSION) {
            return new ValidationResult(false, $type, is_string($version) ? $version : null, ['Unknown or missing schema_version.']);
        }

        $schemaPath = dirname(__DIR__, 2) . '/resources/schemas/evidence/v1/' . $type->schemaFile();
        try {
            $schemaJson = file_get_contents($schemaPath);
            if (!is_string($schemaJson)) {
                return new ValidationResult(false, $type, self::SCHEMA_VERSION, ['Bundled schema is unavailable.']);
            }
            $schema = json_decode($schemaJson, false, 64, JSON_THROW_ON_ERROR);
            if (!$schema instanceof stdClass) {
                return new ValidationResult(false, $type, self::SCHEMA_VERSION, ['Bundled schema is invalid.']);
            }

            $result = (new Validator())->validate($data, $schema);
            if (!$result->isValid()) {
                $error = $result->error();
                return new ValidationResult(
                    false,
                    $type,
                    self::SCHEMA_VERSION,
                    [$error === null ? 'Schema validation failed.' : $this->schemaFailure($error)],
                );
            }

            $record = EvidenceModelFactory::fromObject($data, $type);
            return new ValidationResult(true, $type, self::SCHEMA_VERSION, [], $record);
        } catch (Throwable $error) {
            return new ValidationResult(false, $type, self::SCHEMA_VERSION, [$this->safeError($error)]);
        }
    }

    private function safeError(Throwable $error): string
    {
        return match (true) {
            $error instanceof \JsonException => 'Invalid JSON input.',
            default => $error->getMessage(),
        };
    }

    private function schemaFailure(ValidationError $error): string
    {
        $paths = [];
        $collect = static function (ValidationError $current) use (&$collect, &$paths): void {
            $children = $current->subErrors();
            if ($children === []) {
                $path = '$';
                foreach ($current->data()->fullPath() as $part) {
                    $path .= is_int($part) ? sprintf('[%d]', $part) : '.' . $part;
                }
                $paths[$path] = true;
                return;
            }
            foreach ($children as $child) {
                if (count($paths) >= 8) {
                    return;
                }
                if (!$child instanceof ValidationError) {
                    throw new \UnexpectedValueException('Schema validator returned an invalid child error.');
                }
                $collect($child);
            }
        };
        $collect($error);

        if ($paths === []) {
            return 'JSON Schema validation failed.';
        }

        return 'JSON Schema validation failed at ' . implode(', ', array_keys($paths)) . '.';
    }
}
