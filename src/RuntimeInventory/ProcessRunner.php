<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\RuntimeInventory;

interface ProcessRunner
{
    public function run(ProcessCommand $command): ProcessResult;
}
