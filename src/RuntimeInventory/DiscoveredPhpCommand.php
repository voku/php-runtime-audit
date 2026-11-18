<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\RuntimeInventory;

use InvalidArgumentException;

/** A strict path discovered under one of the collector's bounded runtime directories. */
final readonly class DiscoveredPhpCommand implements ProcessCommandSpec
{
    private const VERSION_PROBE = 'echo json_encode(array("version" => PHP_VERSION, "sapi" => PHP_SAPI, "extensions" => get_loaded_extensions()));';

    private function __construct(private string $path, private string $kind) {}

    public static function fromPath(string $path, string $kind): self
    {
        $fixedDirectory = preg_match('~\A/(?:usr/bin|usr/local/bin|usr/sbin|usr/local/sbin|opt/remi/php[0-9]{2,3}/root/usr/(?:bin|sbin))\z~', dirname($path)) === 1;
        if (!in_array($kind, ['cli', 'fpm'], true)
            || strlen($path) > 512
            || !$fixedDirectory
            || preg_match('~\A/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]+\z~', $path) !== 1
            || preg_match('/(?:\A|\/)\.\.?\z/', $path) === 1
            || ($kind === 'cli' && !preg_match('~/php(?:[0-9]+(?:\.[0-9]+){0,2})?\z~', $path))
            || ($kind === 'fpm' && !preg_match('~/php-fpm(?:[0-9]+(?:\.[0-9]+){0,2})?\z~', $path))) {
            throw new InvalidArgumentException('Discovered PHP command path is outside the bounded allowlist.');
        }

        return new self($path, $kind);
    }

    public function resolvedExecutablePath(): ?string
    {
        return self::resolveAllowedExecutableTarget($this->path, $this->kind);
    }

    public static function resolveAllowedExecutableTarget(string $path, string $kind): ?string
    {
        if (!in_array($kind, ['cli', 'fpm'], true)) {
            return null;
        }

        $resolvedPath = realpath($path);
        if ($resolvedPath === false || !is_file($resolvedPath) || !is_executable($resolvedPath)) {
            return null;
        }
        $directoryIsAllowed = preg_match('~\A/(?:usr/bin|usr/local/bin|usr/sbin|usr/local/sbin|opt/remi/php[0-9]{2,3}/root/usr/(?:bin|sbin))\z~', dirname($resolvedPath)) === 1;
        $basenamePattern = $kind === 'fpm'
            ? '/\Aphp-fpm(?:[0-9]+(?:\.[0-9]+){0,2})?(?:-[A-Za-z0-9._+-]{1,64})?\z/'
            : '/\Aphp(?:[0-9]+(?:\.[0-9]+){0,2})?(?:-[A-Za-z0-9._+-]{1,64})?\z/';

        return $directoryIsAllowed && preg_match($basenamePattern, basename($resolvedPath)) === 1
            ? $resolvedPath
            : null;
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
