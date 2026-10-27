<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\RuntimeInventory;

final readonly class ProcessResult
{
    public function __construct(
        public ?int $exitCode,
        public string $stdout,
        public string $stderr = '',
        public bool $timedOut = false,
        public bool $truncated = false,
        public ?string $error = null,
    ) {}

    public function succeeded(): bool
    {
        return $this->exitCode === 0 && !$this->timedOut && !$this->truncated && $this->error === null;
    }
}
