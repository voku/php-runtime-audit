<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Remediation;

/**
 * The full output of a remediation run: proposals plus any input problems found along the way.
 * A warning is never silently dropped; it always appears in both the JSON and the Markdown report.
 */
final readonly class RemediationPlan
{
    /**
     * @param list<RemediationAction> $actions
     * @param list<string> $warnings explicit record of malformed or unresolvable input, never hidden
     */
    public function __construct(
        public string $generatedAt,
        public ?string $distribution,
        public array $actions,
        public array $warnings,
    ) {}

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'report_schema_version' => '1.0',
            'record_type' => 'remediation_plan',
            'generated_at' => $this->generatedAt,
            'distribution' => $this->distribution,
            'automatic_apply' => false,
            'actions' => array_map(static fn(RemediationAction $action): array => $action->toArray(), $this->actions),
            'warnings' => $this->warnings,
        ];
    }
}
