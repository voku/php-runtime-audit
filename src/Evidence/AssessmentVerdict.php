<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

enum AssessmentVerdict: string
{
    case VerifiedFixed = 'verified_fixed';
    case PotentiallyAffected = 'potentially_affected';
    case Unknown = 'unknown';
    case NeedsInvestigation = 'needs_investigation';
}
