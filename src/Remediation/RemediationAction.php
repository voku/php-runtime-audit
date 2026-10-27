<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Remediation;

/**
 * A single reviewable remediation proposal. Always a proposal: requiresHumanApproval is a
 * hardcoded true on every instance, never a field derived from input, so no crafted or
 * malformed report can produce a plan that claims to need no approval.
 */
final readonly class RemediationAction
{
    public bool $requiresHumanApproval;

    /**
     * @param list<string> $evidenceIds fact_ids from the report's own observation, never fabricated
     * @param list<string> $prerequisites
     * @param list<string> $unknowns explicit open questions; never silently omitted
     */
    public function __construct(
        public string $actionId,
        public string $subjectId,
        public string $subjectLabel,
        public string $cve,
        public string $advisoryTitle,
        public RemediationActionKind $kind,
        public string $why,
        public array $evidenceIds,
        public array $prerequisites,
        public string $action,
        public string $risk,
        public string $rollback,
        public string $verification,
        public array $unknowns,
        public bool $maintenanceWindowRequired,
    ) {
        $this->requiresHumanApproval = true;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'record_type' => 'remediation_action',
            'schema_version' => '1.0',
            'action_id' => $this->actionId,
            'subject_id' => $this->subjectId,
            'subject_label' => $this->subjectLabel,
            'cve' => $this->cve,
            'advisory_title' => $this->advisoryTitle,
            'kind' => $this->kind->value,
            'requires_human_approval' => $this->requiresHumanApproval,
            'maintenance_window_required' => $this->maintenanceWindowRequired,
            'why' => $this->why,
            'evidence_ids' => $this->evidenceIds,
            'prerequisites' => $this->prerequisites,
            'action' => $this->action,
            'risk' => $this->risk,
            'rollback' => $this->rollback,
            'verification' => $this->verification,
            'unknown' => $this->unknowns,
        ];
    }
}
