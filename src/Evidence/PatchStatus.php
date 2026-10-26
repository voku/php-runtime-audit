<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

enum PatchStatus: string
{
    case VerifiedFixed = 'verified_fixed';
    case PotentiallyAffected = 'potentially_affected';
    case Unknown = 'unknown';
}
