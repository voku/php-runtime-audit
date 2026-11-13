<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\RuntimeInventory;

final class DpkgPackageStatus
{
    private const WANTED_ACTIONS = ['unknown', 'install', 'hold', 'deinstall', 'purge'];
    private const ERROR_STATES = ['ok', 'reinstreq'];
    private const CURRENT_STATES = [
        'not-installed', 'config-files', 'half-installed', 'unpacked', 'half-configured',
        'triggers-awaited', 'triggers-pending', 'installed',
    ];

    public static function hasValidFields(string $status): bool
    {
        return self::fields($status) !== null;
    }

    public static function isInstalled(string $status): bool
    {
        $fields = self::fields($status);

        return $fields !== null && $fields[2] === 'installed';
    }

    public static function isAbsent(string $status): bool
    {
        $fields = self::fields($status);

        return $fields !== null && in_array($fields[2], ['not-installed', 'config-files'], true);
    }

    public static function hasVerifiedIntegrityStatus(string $status): bool
    {
        $fields = self::fields($status);

        return $fields !== null
            && $fields[1] === 'ok'
            && $fields[2] === 'installed';
    }

    /** @return array{string, string, string}|null */
    private static function fields(string $status): ?array
    {
        $fields = preg_split('/\s+/', trim($status));
        if (!is_array($fields) || count($fields) !== 3) {
            return null;
        }
        if (!in_array($fields[0], self::WANTED_ACTIONS, true)
            || !in_array($fields[1], self::ERROR_STATES, true)
            || !in_array($fields[2], self::CURRENT_STATES, true)) {
            return null;
        }

        return [$fields[0], $fields[1], $fields[2]];
    }
}
