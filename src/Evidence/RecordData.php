<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

use InvalidArgumentException;
use stdClass;

/** @internal Helpers used after JSON Schema validation. */
final class RecordData
{
    /** @return array<string, mixed> */
    public static function object(mixed $value, string $label): array
    {
        if ($value instanceof stdClass) {
            $value = get_object_vars($value);
        } elseif (!is_array($value) || array_is_list($value)) {
            throw new InvalidArgumentException(sprintf('%s must be an object.', $label));
        }

        $object = [];
        foreach ($value as $key => $item) {
            if (!is_string($key)) {
                throw new InvalidArgumentException(sprintf('%s must have string property names.', $label));
            }
            $object[$key] = $item;
        }
        return $object;
    }

    /** @return list<mixed> */
    public static function list(mixed $value, string $label): array
    {
        if (!is_array($value) || !array_is_list($value)) {
            throw new InvalidArgumentException(sprintf('%s must be a list.', $label));
        }

        return $value;
    }

    /** @param array<string, mixed> $data */
    public static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? null;
        if (!is_string($value) || trim($value) === '') {
            throw new InvalidArgumentException(sprintf('%s must be a non-empty string.', $key));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $data
     * @return list<string>
     */
    public static function stringList(array $data, string $key): array
    {
        $values = self::list($data[$key] ?? null, $key);
        foreach ($values as $value) {
            if (!is_string($value) || trim($value) === '') {
                throw new InvalidArgumentException(sprintf('%s must contain non-empty strings.', $key));
            }
        }

        return $values;
    }

    /**
     * @param class-string<\BackedEnum> $enumClass
     * @param array<string, mixed> $data
     */
    public static function enumValue(string $enumClass, array $data, string $key): object
    {
        $value = self::string($data, $key);
        $enum = $enumClass::tryFrom($value);
        if ($enum === null) {
            throw new InvalidArgumentException(sprintf('%s has an unsupported value.', $key));
        }

        return $enum;
    }

    public static function timestamp(string $value, string $field): string
    {
        if (preg_match('/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})$/D', $value) !== 1) {
            throw new InvalidArgumentException(sprintf('%s must be an ISO 8601 timestamp with a timezone.', $field));
        }

        try {
            new \DateTimeImmutable($value);
            $dateErrors = \DateTimeImmutable::getLastErrors();
            if ($dateErrors !== false && ($dateErrors['warning_count'] > 0 || $dateErrors['error_count'] > 0)) {
                throw new InvalidArgumentException(sprintf('%s must be a valid timestamp.', $field));
            }
        } catch (\Throwable) {
            throw new InvalidArgumentException(sprintf('%s must be a valid timestamp.', $field));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $data
     * @param list<string> $allowed
     */
    public static function rejectUnknownKeys(array $data, array $allowed, string $record): void
    {
        $unknown = array_diff(array_keys($data), $allowed);
        if ($unknown !== []) {
            throw new InvalidArgumentException(sprintf('%s contains undeclared fields.', $record));
        }
    }

    /** @return list<array<string, mixed>> */
    public static function objectList(mixed $value, string $label): array
    {
        $items = self::list($value, $label);
        return array_map(static fn(mixed $item): array => self::object($item, $label . ' item'), $items);
    }
}
