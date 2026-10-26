<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

enum FindingStatus: string
{
    case Confirmed = 'confirmed';
    case NeedsValidation = 'needs_validation';
    case Rejected = 'rejected';
}
