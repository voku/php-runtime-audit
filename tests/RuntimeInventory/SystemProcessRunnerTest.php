<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\RuntimeInventory;

use PHPUnit\Framework\TestCase;
use voku\PhpRuntimeAudit\RuntimeInventory\DiscoveredPhpCommand;
use voku\PhpRuntimeAudit\RuntimeInventory\ProcessCommand;
use voku\PhpRuntimeAudit\RuntimeInventory\ProcessCommandSpec;
use voku\PhpRuntimeAudit\RuntimeInventory\SystemProcessRunner;

final class SystemProcessRunnerTest extends TestCase
{
    public function test_custom_command_spec_cannot_bypass_the_runner_allowlist(): void
    {
        $command = new class implements ProcessCommandSpec {
            public function id(): string
            {
                return 'custom-command';
            }

            public function argv(): array
            {
                return ['/usr/bin/true'];
            }

            public function timeoutSeconds(): float
            {
                return 1.0;
            }

            public function outputLimitBytes(): int
            {
                return 1024;
            }

            public function executablePath(): string
            {
                return '/usr/bin/true';
            }

            public function isPhpCli(): bool
            {
                return false;
            }

            public function isFpm(): bool
            {
                return false;
            }
        };

        $result = (new SystemProcessRunner())->run($command);

        self::assertNull($result->exitCode);
        self::assertSame('process request is outside the bounded execution policy', $result->error);
    }

    public function test_discovered_php_target_must_resolve_to_a_php_executable(): void
    {
        self::assertNull(DiscoveredPhpCommand::resolveAllowedExecutableTarget('/bin/sh', 'cli'));
        self::assertNull(DiscoveredPhpCommand::resolveAllowedExecutableTarget('/bin/sh', 'fpm'));
    }

    public function test_apk_package_query_allows_only_its_canonical_usr_merged_target(): void
    {
        $root = sys_get_temp_dir() . '/pra-apk-usr-merged-' . bin2hex(random_bytes(6));
        mkdir($root . '/usr/sbin', 0777, true);
        file_put_contents($root . '/usr/sbin/apk', 'fixture apk executable');
        chmod($root . '/usr/sbin/apk', 0755);
        self::assertTrue(symlink('usr/sbin', $root . '/sbin'));

        try {
            $allowedPathsMethod = new \ReflectionMethod(SystemProcessRunner::class, 'allowedCanonicalExecutablePaths');
            $allowedPaths = $allowedPathsMethod->invoke(null, ProcessCommand::ApkPackages);
            self::assertSame(['/sbin/apk', '/usr/sbin/apk'], $allowedPaths);

            $resolveMethod = new \ReflectionMethod(SystemProcessRunner::class, 'resolveAllowlistedExecutable');
            $fixtureAllowedPaths = [$root . '/sbin/apk', $root . '/usr/sbin/apk'];
            self::assertSame(
                $root . '/usr/sbin/apk',
                $resolveMethod->invoke(null, $root . '/sbin/apk', $fixtureAllowedPaths),
            );

            mkdir($root . '/usr/bin', 0777, true);
            file_put_contents($root . '/usr/bin/apk', 'unapproved apk target');
            chmod($root . '/usr/bin/apk', 0755);
            self::assertTrue(symlink('usr/bin', $root . '/unapproved-sbin'));
            self::assertNull($resolveMethod->invoke(null, $root . '/unapproved-sbin/apk', $fixtureAllowedPaths));
        } finally {
            foreach ([$root . '/sbin', $root . '/unapproved-sbin'] as $link) {
                if (is_link($link)) {
                    unlink($link);
                }
            }
            foreach ([$root . '/usr/sbin/apk', $root . '/usr/bin/apk'] as $path) {
                if (is_file($path)) {
                    unlink($path);
                }
            }
            foreach ([$root . '/usr/sbin', $root . '/usr/bin', $root . '/usr', $root] as $directory) {
                if (is_dir($directory)) {
                    rmdir($directory);
                }
            }
        }
    }
}
