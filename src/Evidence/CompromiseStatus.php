<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

enum CompromiseStatus: string
{
    case NoneObserved = 'none_observed';
    case Suspected = 'suspected';
    case Confirmed = 'confirmed';
    case Unknown = 'unknown';
}
