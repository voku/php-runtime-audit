<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\RuntimeInventory;

use InvalidArgumentException;

/** A strict path discovered under one of the collector's bounded runtime directories. */
final readonly class DiscoveredPhpCommand implements ProcessCommandSpec
{
    private const VERSION_PROBE = 'echo json_encode(["version" => PHP_VERSION, "sapi" => PHP_SAPI, "extensions" => get_loaded_extensions()]);';

    private function __construct(private string $path, private string $kind) {}

    /** @param list<string> $pathDirectories */
    public static function fromPath(string $path, string $kind, array $pathDirectories = []): self
    {
        foreach ($pathDirectories as $directory) {
            if (strlen($directory) > 512 || !str_starts_with($directory, '/')
                || preg_match('/[\x00-\x1F\x7F]/', $directory) === 1
                || preg_match('~\A/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]*\z~', $directory) !== 1
                || preg_match('~(?:\A|/)\.\.?(?:/|\z)~', $directory) === 1) {
                throw new InvalidArgumentException('PATH discovery directory is outside the bounded path policy.');
            }
        }
        $fixedDirectory = preg_match('~\A/(?:usr/bin|usr/local/bin|usr/sbin|usr/local/sbin|opt/remi/php[0-9]{2,3}/root/usr/(?:bin|sbin))\z~', dirname($path)) === 1;
        $pathDirectory = in_array(dirname($path), $pathDirectories, true);
        if (!in_array($kind, ['cli', 'fpm'], true)
            || strlen($path) > 512
            || (!$fixedDirectory && !$pathDirectory)
            || preg_match('~\A/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]+\z~', $path) !== 1
            || preg_match('/(?:\A|\/)\.\.?\z/', $path) === 1
            || ($kind === 'cli' && !preg_match('~/php(?:[0-9]+(?:\.[0-9]+){0,2})?\z~', $path))
            || ($kind === 'fpm' && !preg_match('~/php-fpm(?:[0-9]+(?:\.[0-9]+){0,2})?\z~', $path))) {
            throw new InvalidArgumentException('Discovered PHP command path is outside the bounded allowlist.');
        }

        return new self($path, $kind);
    }

    public function id(): string
    {
        return 'discovered-' . $this->kind . '-' . substr(hash('sha256', $this->path), 0, 24);
    }

    /** @return list<string> */
    public function argv(): array
    {
        return $this->kind === 'cli'
            ? [$this->path, '-n', '-r', self::VERSION_PROBE]
            : [$this->path, '-n', '-v'];
    }

    public function timeoutSeconds(): float
    {
        return 3.0;
    }

    public function outputLimitBytes(): int
    {
        return 16_384;
    }

    public function executablePath(): string
    {
        return $this->path;
    }

    public function isPhpCli(): bool
    {
        return $this->kind === 'cli';
    }

    public function isFpm(): bool
    {
        return $this->kind === 'fpm';
    }
}
