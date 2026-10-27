<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Remediation;

/**
 * A fixed, small vocabulary of remediation action kinds. Deliberately closed: every proposal
 * maps to one of these, never to free-form text built from advisory or package data.
 */
enum RemediationActionKind: string
{
    case NoActionRequired = 'no_action_required';
    case UpgradePackage = 'upgrade_package';
    case VerifyWorkerIdentity = 'verify_worker_identity';
    case AwaitVendorEvidence = 'await_vendor_evidence';
    case InvestigateConfiguration = 'investigate_configuration';
    case InvestigateUnknownSubject = 'investigate_unknown_subject';
}
