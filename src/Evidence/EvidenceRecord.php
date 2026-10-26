<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

interface EvidenceRecord
{
    public function recordType(): RecordType;

    /** @return array<string, mixed> */
    public function toArray(): array;
}
