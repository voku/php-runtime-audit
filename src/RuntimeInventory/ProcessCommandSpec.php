<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\RuntimeInventory;

/** A bounded argument vector for a local, read-only probe. */
interface ProcessCommandSpec
{
    /** Stable identifier used to bind command output to provenance. */
    public function id(): string;

    /** @return list<string> */
    public function argv(): array;

    public function timeoutSeconds(): float;

    public function outputLimitBytes(): int;

    public function executablePath(): string;

    public function isPhpCli(): bool;

    public function isFpm(): bool;
}
