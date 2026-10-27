<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\RuntimeInventory;

use PHPUnit\Framework\TestCase;

final class InventoryCliArgumentsTest extends TestCase
{
    public function testDisabledArgumentCaptureCannotTurnFixtureRequestIntoHostAudit(): void
    {
        $root = dirname(__DIR__, 2);
        $process = proc_open(
            [PHP_BINARY, '-d', 'register_argc_argv=0', $root . '/bin/php-runtime-audit-inventory', '--fixture', $root . '/tests/fixtures/runtime/debian-fpm'],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            $root,
        );
        self::assertIsResource($process);
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exit = proc_close($process);

        self::assertSame(2, $exit);
        self::assertSame('', $stdout);
        self::assertIsString($stderr);
        self::assertStringContainsString('CLI argument capture is unavailable', $stderr);
        self::assertStringNotContainsString('Undefined variable', $stderr);
    }
    public function testOversizedFixtureIsRejectedBeforeAllocationUnderLowMemory(): void
    {
        $root = dirname(__DIR__, 2);
        $fixture = sys_get_temp_dir() . '/pra-oversized-' . bin2hex(random_bytes(6));
        self::assertTrue(mkdir($fixture));
        try {
            $file = fopen($fixture . '/commands.json', 'w');
            self::assertIsResource($file);
            self::assertTrue(ftruncate($file, 67_108_864));
            fclose($file);
            $process = proc_open(
                [PHP_BINARY, '-d', 'memory_limit=16M', '-d', 'register_argc_argv=1', $root . '/bin/php-runtime-audit-inventory', '--fixture', $fixture],
                [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                $pipes,
                $root,
            );
            self::assertIsResource($process);
            fclose($pipes[0]);
            $stdout = stream_get_contents($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $exit = proc_close($process);
            self::assertSame(2, $exit);
            self::assertSame('', $stdout);
            self::assertIsString($stderr);
            self::assertStringContainsString('Fixture command data is unreadable or too large', $stderr);
            self::assertStringNotContainsString('Allowed memory size', $stderr);
        } finally {
            unlink($fixture . '/commands.json');
            rmdir($fixture);
        }
    }

}
