<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

enum ApplicabilityState: string
{
    case True = 'true';
    case False = 'false';
    case Unknown = 'unknown';
}
