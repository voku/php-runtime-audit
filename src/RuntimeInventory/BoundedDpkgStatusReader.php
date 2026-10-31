<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\RuntimeInventory;

use RuntimeException;

/**
 * Reads untrusted local dpkg metadata without subprocesses or network access.
 * A parsed package is not proof of vendor authenticity or loaded-worker patch status.
 *
 * @phpstan-type PhpPackage array{name: non-empty-string, version: non-empty-string}
 * @phpstan-type DpkgObservation array{content: string, packages: list<PhpPackage>}
 */
final readonly class BoundedDpkgStatusReader
{
    private const MAX_STATUS_BYTES = 8_388_608;
    private const MAX_PHP_PACKAGES = 256;
    private const MAX_PHP_PACKAGE_NAME_BYTES = 128;

    public function __construct(private string $root) {}

    /** @return DpkgObservation */
    public function observe(): array
    {
        $root = realpath($this->root);
        if ($root === false || !is_dir($root)) {
            throw new RuntimeException('Dpkg observation root is unavailable.');
        }
        $path = rtrim($root, '/') . '/var/lib/dpkg/status';
        $part = rtrim($root, '/');
        foreach (['var', 'lib', 'dpkg', 'status'] as $segment) {
            $part .= '/' . $segment;
            if (is_link($part)) {
                throw new RuntimeException('Symlink encountered in dpkg status path.');
            }
        }
        $before = @lstat($path);
        if (!is_array($before) || ($before['mode'] & 0170000) !== 0100000
            || $before['size'] < 1 || $before['size'] > self::MAX_STATUS_BYTES) {
            throw new RuntimeException('Dpkg status is missing, non-regular or oversized.');
        }
        $stream = @fopen($path, 'rb');
        if ($stream === false) {
            throw new RuntimeException('Dpkg status cannot be opened for reading.');
        }
        try {
            $opened = fstat($stream);
            if (!is_array($opened) || !self::sameFile($before, $opened)) {
                throw new RuntimeException('Dpkg status changed before read.');
            }
            $contents = stream_get_contents($stream, self::MAX_STATUS_BYTES + 1);
            $atEnd = feof($stream);
            $closed = fstat($stream);
            $after = @lstat($path);
            if (!is_string($contents) || !$atEnd || strlen($contents) !== $opened['size']
                || !is_array($closed)
                || !self::sameFile($opened, $closed) || !self::sameFile($opened, $after)) {
                throw new RuntimeException('Dpkg status read was incomplete or changed.');
            }
        } finally {
            fclose($stream);
        }

        return [
            'content' => $contents,
            'packages' => self::parseInstalledPhpPackages($contents),
        ];
    }

    /**
     * @param array<string|int, int> $first
     * @param array<string|int, int> $second
     */
    private static function sameFile(array $first, array $second): bool
    {
        foreach (['dev', 'ino', 'size', 'mtime', 'ctime'] as $field) {
            if (!isset($first[$field], $second[$field]) || $first[$field] !== $second[$field]) {
                return false;
            }
        }

        return ($second['mode'] & 0170000) === 0100000;
    }

    /** @return list<PhpPackage> */
    private static function parseInstalledPhpPackages(string $contents): array
    {
        if (str_contains($contents, "\0")) {
            throw new RuntimeException('NUL byte in dpkg status.');
        }
        $packages = [];
        $seen = [];
        foreach (preg_split('/\r?\n[ \t]*\r?\n/', $contents) ?: [] as $paragraph) {
            if (trim($paragraph) === '') {
                continue;
            }
            $fields = [];
            foreach (preg_split('/\r?\n/', $paragraph) ?: [] as $line) {
                if ($line === '' || $line[0] === ' ' || $line[0] === "\t") {
                    continue;
                }
                if (preg_match('/\A([A-Za-z][A-Za-z0-9-]*):(?:[ \t]+([^\r\n]*))?\z/D', $line, $match) !== 1) {
                    throw new RuntimeException('Malformed dpkg status field.');
                }
                if (in_array($match[1], ['Package', 'Version', 'Status'], true)) {
                    if (isset($fields[$match[1]])) {
                        throw new RuntimeException('Duplicate dpkg identity field.');
                    }
                    $fields[$match[1]] = $match[2] ?? '';
                }
            }
            $name = $fields['Package'] ?? '';
            if (preg_match('/\A(?:php(?:[0-9.]*(?:-[a-z0-9.+-]+)?)?|libapache2-mod-php[0-9.]*|mod_php[0-9.]*|php-main)\z/iD', $name) !== 1) {
                continue;
            }
            if (strlen($name) > self::MAX_PHP_PACKAGE_NAME_BYTES) {
                throw new RuntimeException('PHP package name exceeds bounded observation limit.');
            }
            if (isset($seen[$name])) {
                throw new RuntimeException('Duplicate PHP package in dpkg status.');
            }
            $seen[$name] = true;
            $version = $fields['Version'] ?? '';
            if (preg_match('/\A[0-9][A-Za-z0-9.+:~_-]{0,127}\z/D', $version) !== 1
                || !isset($fields['Status']) || $fields['Status'] === '') {
                throw new RuntimeException('Malformed PHP package metadata.');
            }
            if ($fields['Status'] !== 'install ok installed') {
                continue;
            }
            $packages[] = ['name' => $name, 'version' => $version];
            if (count($packages) > self::MAX_PHP_PACKAGES) {
                throw new RuntimeException('Too many PHP package records in dpkg status.');
            }
        }

        return $packages;
    }
}
