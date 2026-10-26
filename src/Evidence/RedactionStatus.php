<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

enum RedactionStatus: string
{
    case NotApplied = 'not_applied';
    case Partial = 'partial';
    case Complete = 'complete';
    case Unknown = 'unknown';
}
