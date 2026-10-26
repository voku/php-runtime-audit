<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\AuditProfiles;

enum AuditIntent: string
{
    case RuntimePatch = 'runtime-patch';
    case Configuration = 'configuration';
    case IncidentTriage = 'incident-triage';
    case SourceReview = 'source-review';
}
