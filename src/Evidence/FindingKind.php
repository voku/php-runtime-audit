<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

enum FindingKind: string
{
    case Vulnerability = 'vulnerability';
    case CompromiseIndicator = 'compromise_indicator';
    case Configuration = 'configuration';
    case Unknown = 'unknown';
}
