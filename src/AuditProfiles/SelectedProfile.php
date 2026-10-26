<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\AuditProfiles;

final readonly class SelectedProfile
{
    public function __construct(
        public string $id,
        public string $reason,
    ) {}

    /** @return array{id: string, reason: string} */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'reason' => $this->reason,
        ];
    }
}
