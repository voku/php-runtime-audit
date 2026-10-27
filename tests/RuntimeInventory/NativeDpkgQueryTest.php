<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\RuntimeInventory;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use voku\PhpRuntimeAudit\RuntimeInventory\ProcessCommand;

final class NativeDpkgQueryTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function packageNames(): iterable
    {
        yield 'FPM without Apache' => ['php8.2-fpm'];
        yield 'Apache without FPM' => ['libapache2-mod-php8.2'];
    }

    #[DataProvider('packageNames')]
    public function test_native_query_accepts_each_independently_installed_runtime(string $name): void
    {
        $argv = ProcessCommand::DpkgPackages->argv();
        if (!is_executable($argv[0])) {
            self::markTestSkipped('Native dpkg-query is unavailable on this platform.');
        }
        $database = sys_get_temp_dir() . '/pra-native-dpkg-' . bin2hex(random_bytes(6));
        self::assertTrue(mkdir($database));
        try {
            file_put_contents($database . '/status', "Package: $name\nStatus: install ok installed\nArchitecture: amd64\nVersion: 8.2.35-1~deb12u1\nMaintainer: Synthetic fixture <fixture@example.invalid>\nDescription: Synthetic native-query test data\n\n");
            array_splice($argv, 1, 0, ['--admindir=' . $database]);
            $process = proc_open($argv, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            self::assertIsResource($process);
            fclose($pipes[0]);
            $stdout = stream_get_contents($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $exit = proc_close($process);
            self::assertSame(0, $exit, is_string($stderr) ? $stderr : 'Native dpkg query failed.');
            self::assertSame($name . "\t8.2.35-1~deb12u1\n", $stdout);
        } finally {
            unlink($database . '/status');
            rmdir($database);
        }
    }
}
