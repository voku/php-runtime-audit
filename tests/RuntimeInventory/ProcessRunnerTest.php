<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\RuntimeInventory;

use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use voku\PhpRuntimeAudit\RuntimeInventory\ProcessCommand;
use voku\PhpRuntimeAudit\RuntimeInventory\SystemProcessRunner;

final class ProcessRunnerTest extends TestCase
{
    public function test_inventory_commands_are_fixed_absolute_argv_with_bounded_limits(): void
    {
        foreach (ProcessCommand::cases() as $command) {
            $argv = $command->argv();
            self::assertNotSame([], $argv);
            self::assertStringStartsWith('/', $argv[0]);
            self::assertGreaterThan(0, $command->timeoutSeconds());
            self::assertLessThanOrEqual(10, $command->timeoutSeconds());
            self::assertGreaterThan(0, $command->outputLimitBytes());
            self::assertLessThanOrEqual(262_144, $command->outputLimitBytes());
        }
    }

    public function test_system_runner_times_out_a_fixed_test_process(): void
    {
        $result = $this->execute([PHP_BINARY, '-r', 'usleep(500000); echo "done";'], 0.05, 128);

        self::assertTrue($result->timedOut);
        self::assertFalse($result->succeeded());
    }

    public function test_system_runner_caps_output_even_when_child_exits_immediately(): void
    {
        $result = $this->execute([PHP_BINARY, '-r', 'fwrite(STDOUT, str_repeat("x", 100000));'], 2.0, 128);

        self::assertTrue($result->truncated);
        self::assertLessThanOrEqual(128, strlen($result->stdout) + strlen($result->stderr));
        self::assertFalse($result->succeeded());
    }

    /** @param list<string> $argv */
    private function execute(array $argv, float $timeoutSeconds, int $outputLimitBytes): \voku\PhpRuntimeAudit\RuntimeInventory\ProcessResult
    {
        $method = new ReflectionMethod(SystemProcessRunner::class, 'execute');
        $result = $method->invoke(new SystemProcessRunner(), $argv, $timeoutSeconds, $outputLimitBytes);
        self::assertInstanceOf(\voku\PhpRuntimeAudit\RuntimeInventory\ProcessResult::class, $result);

        return $result;
    }
}
