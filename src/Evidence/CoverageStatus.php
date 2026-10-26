<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

enum CoverageStatus: string
{
    case Attempted = 'attempted';
    case Skipped = 'skipped';
    case Blocked = 'blocked';
}
