<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\AuditProfiles;

use InvalidArgumentException;

enum Applicability: string
{
    case True = 'true';
    case False = 'false';
    case Unknown = 'unknown';

    public static function fromInput(mixed $value, string $field): self
    {
        return match ($value) {
            true => self::True,
            false => self::False,
            null => self::Unknown,
            default => throw new InvalidArgumentException(sprintf(
                'Fact "%s" must be true, false, or unknown.',
                $field,
            )),
        };
    }
}
