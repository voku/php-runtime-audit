<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\AuditProfiles;

use InvalidArgumentException;

final readonly class AuditFacts
{
    /**
     * @param list<string>|null $extensions
     * @param array<string, Applicability> $configuration
     */
    private function __construct(
        public ?string $phpVersion,
        public ?string $sapi,
        public ?string $distribution,
        public ?string $vendor,
        public Applicability $container,
        public ?array $extensions,
        public array $configuration,
    ) {}

    /** @param array<string, mixed> $facts */
    public static function fromArray(array $facts): self
    {
        $allowedKeys = [
            'php_version',
            'sapi',
            'distribution',
            'vendor',
            'container',
            'extensions',
            'configuration',
        ];
        $unknownKeys = array_diff(array_keys($facts), $allowedKeys);
        if ($unknownKeys !== []) {
            throw new InvalidArgumentException('Unsupported fact field(s) are present.');
        }

        $extensions = self::extensions($facts['extensions'] ?? null);
        $configuration = self::configuration($facts['configuration'] ?? []);

        return new self(
            phpVersion: self::optionalString($facts['php_version'] ?? null, 'php_version'),
            sapi: self::optionalString($facts['sapi'] ?? null, 'sapi', lowercase: true),
            distribution: self::optionalString($facts['distribution'] ?? null, 'distribution', lowercase: true),
            vendor: self::optionalString($facts['vendor'] ?? null, 'vendor', lowercase: true),
            container: Applicability::fromInput($facts['container'] ?? null, 'container'),
            extensions: $extensions,
            configuration: $configuration,
        );
    }

    private static function optionalString(mixed $value, string $field, bool $lowercase = false): ?string
    {
        if ($value === null) {
            return null;
        }

        if (!is_string($value)) {
            throw new InvalidArgumentException(sprintf('Fact "%s" must be a string or unknown.', $field));
        }

        $value = trim($value);
        if ($value === '') {
            return null;
        }

        if (strlen($value) > 128 || preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
            throw new InvalidArgumentException(sprintf('Fact "%s" is too long or contains control characters.', $field));
        }

        if ($field === 'vendor' && preg_match('/\A[a-zA-Z0-9][a-zA-Z0-9._+-]{0,63}\z/', $value) !== 1) {
            throw new InvalidArgumentException('Fact "vendor" must be a bounded vendor identifier.');
        }

        return $lowercase ? strtolower($value) : $value;
    }

    /** @return list<string>|null */
    private static function extensions(mixed $value): ?array
    {
        if ($value === null) {
            return null;
        }

        if (!is_array($value) || !array_is_list($value)) {
            throw new InvalidArgumentException('Fact "extensions" must be a list of extension names or unknown.');
        }

        if (count($value) > 128) {
            throw new InvalidArgumentException('Fact "extensions" contains too many extension names.');
        }

        $extensions = [];
        foreach ($value as $extension) {
            if (!is_string($extension) || strlen($extension) > 64 || preg_match('/\A[a-zA-Z0-9_-]+\z/', $extension) !== 1) {
                throw new InvalidArgumentException('Fact "extensions" contains an invalid extension name.');
            }

            $extensions[] = strtolower($extension);
        }

        $extensions = array_values(array_unique($extensions));
        sort($extensions, SORT_STRING);

        return $extensions;
    }

    /** @return array<string, Applicability> */
    private static function configuration(mixed $value): array
    {
        if (!is_array($value)) {
            throw new InvalidArgumentException('Fact "configuration" must be an object of named boolean facts.');
        }

        if (count($value) > 128) {
            throw new InvalidArgumentException('Fact "configuration" contains too many settings.');
        }

        $configuration = [];
        foreach ($value as $name => $setting) {
            if (!is_string($name) || strlen($name) > 64 || preg_match('/\A[a-zA-Z0-9][a-zA-Z0-9_.-]*\z/', $name) !== 1) {
                throw new InvalidArgumentException('Fact "configuration" contains an invalid setting name.');
            }

            $configuration[$name] = Applicability::fromInput($setting, 'configuration.' . $name);
        }

        ksort($configuration, SORT_STRING);

        return $configuration;
    }
}
