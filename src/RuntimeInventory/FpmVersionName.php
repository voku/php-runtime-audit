<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\RuntimeInventory;

final class FpmVersionName
{
    public static function fromProcessName(string $name): ?string
    {
        if (preg_match('/\Aphp-fpm([0-9]+\.[0-9]{1,2}|[0-9]{2,3})\z/i', $name, $matches) !== 1) {
            return null;
        }

        return str_contains($matches[1], '.')
            ? $matches[1]
            : self::fromCompactBranch($matches[1]);
    }

    public static function fromCompactBranch(string $branch): ?string
    {
        if (preg_match('/\A[0-9]{2,3}\z/', $branch) !== 1) {
            return null;
        }

        return $branch[0] . '.' . substr($branch, 1);
    }
}
