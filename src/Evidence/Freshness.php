<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

enum Freshness: string
{
    case Fresh = 'fresh';
    case Stale = 'stale';
    case Unknown = 'unknown';

    public static function fromDigests(?string $captured, ?string $current): self
    {
        if ($captured === null || $current === null) {
            return self::Unknown;
        }

        return hash_equals($captured, $current) ? self::Fresh : self::Stale;
    }
}
