<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\RuntimeInventory;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use voku\PhpRuntimeAudit\Advisories\AdvisoryCatalog;
use voku\PhpRuntimeAudit\Advisories\AdvisoryEvaluator;
use voku\PhpRuntimeAudit\RuntimeInventory\FixtureProcessRunner;
use voku\PhpRuntimeAudit\RuntimeInventory\RuntimeInventoryCollector;

final class ModernRpmDatabaseTest extends TestCase
{
    /** @return iterable<string, array{string, bool}> */
    public static function databasePaths(): iterable
    {
        yield 'modern SQLite' => ['/usr/lib/sysimage/rpm/rpmdb.sqlite', true];
        yield 'legacy-path SQLite' => ['/var/lib/rpm/rpmdb.sqlite', true];
        yield 'legacy Berkeley DB' => ['/var/lib/rpm/Packages', true];
        yield 'directory-shaped regular marker is not a database' => ['/usr/lib/sysimage/rpm', false];
    }

    #[DataProvider('databasePaths')]
    public function test_only_supported_regular_database_files_enable_rpm_query_evidence(string $databasePath, bool $known): void
    {
        $root = sys_get_temp_dir() . '/pra-rpm-layout-' . bin2hex(random_bytes(6));
        $directories = [$root];
        $files = [];
        try {
            foreach (['/usr/bin/rpm', '/etc/os-release', $databasePath, '/commands.json'] as $path) {
                $directory = dirname($root . $path);
                $missing = [];
                while (!is_dir($directory)) {
                    $missing[] = $directory;
                    $directory = dirname($directory);
                }
                foreach (array_reverse($missing) as $directory) {
                    self::assertTrue(mkdir($directory));
                    $directories[] = $directory;
                }
                $files[] = $root . $path;
                file_put_contents($root . $path, 'synthetic layout marker');
            }
            file_put_contents($root . '/etc/os-release', "ID=rhel\nVERSION_ID=10\n");
            file_put_contents($root . '/commands.json', json_encode(['commands' => [
                'rpm-packages' => ['exit_code' => 0, 'stdout' => "php-fpm\t8.3.36-1.el10_2\tx86_64\n"],
            ]], JSON_THROW_ON_ERROR));
            $inventory = (new RuntimeInventoryCollector(new FixtureProcessRunner($root), $root))->collect();
            self::assertSame($known ? 'rpm' : null, $inventory['package_manager']);
            self::assertSame($known ? 'attempted' : 'unknown', $inventory['package_inventory_state']);
            self::assertSame($known ? [['name' => 'php-fpm', 'version' => '8.3.36-1.el10_2', 'architecture' => 'x86_64']] : [], $inventory['packages']);
        } finally {
            foreach (array_reverse($files) as $file) {
                unlink($file);
            }
            $directories = array_unique($directories);
            usort($directories, static fn(string $left, string $right): int => strlen($right) <=> strlen($left));
            foreach ($directories as $directory) {
                rmdir($directory);
            }
        }
    }

    public function test_duplicate_package_identity_rows_are_omitted_and_block_package_coverage(): void
    {
        $root = sys_get_temp_dir() . '/pra-rpm-multilib-' . bin2hex(random_bytes(6));
        $directories = [$root];
        $files = [];
        try {
            foreach (['/usr/bin/rpm', '/etc/os-release', '/usr/lib/sysimage/rpm/rpmdb.sqlite', '/commands.json'] as $path) {
                $directory = dirname($root . $path);
                $missing = [];
                while (!is_dir($directory)) {
                    $missing[] = $directory;
                    $directory = dirname($directory);
                }
                foreach (array_reverse($missing) as $directory) {
                    self::assertTrue(mkdir($directory));
                    $directories[] = $directory;
                }
                $files[] = $root . $path;
                file_put_contents($root . $path, 'synthetic layout marker');
            }
            file_put_contents($root . '/etc/os-release', "ID=rhel\nVERSION_ID=10\n");
            file_put_contents($root . '/commands.json', json_encode(['commands' => [
                'rpm-packages' => [
                    'exit_code' => 0,
                    'stdout' => "php-fpm\t8.3.36-1.el10_2\tx86_64\nphp-fpm\t8.3.36-1.el10_2\tx86_64\n",
                ],
            ]], JSON_THROW_ON_ERROR));

            $inventory = (new RuntimeInventoryCollector(new FixtureProcessRunner($root), $root))->collect();
            self::assertSame('incomplete', $inventory['package_inventory_state']);
            self::assertSame([], $inventory['packages']);

            $identityFacts = array_values(array_filter(
                $inventory['facts'],
                static fn(array $fact): bool => in_array($fact['key'], [
                    'packages.identity_ambiguous',
                    'packages.identity_ambiguous_count',
                ], true),
            ));
            self::assertSame([
                ['key' => 'packages.identity_ambiguous', 'value' => true],
                ['key' => 'packages.identity_ambiguous_count', 'value' => 1],
            ], array_map(
                static fn(array $fact): array => ['key' => $fact['key'], 'value' => $fact['value']],
                $identityFacts,
            ));

            $packageCoverage = array_values(array_filter(
                $inventory['coverage'],
                static fn(array $coverage): bool => $coverage['check_id'] === 'runtime.packages',
            ));
            self::assertCount(1, $packageCoverage);
            self::assertSame('blocked', $packageCoverage[0]['status']);
            self::assertStringContainsString('same name, version, and architecture', (string) $packageCoverage[0]['gap']);

            $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());
            self::assertSame(
                count($evaluation['assessments']),
                count(array_unique(array_column($evaluation['assessments'], 'record_id'))),
            );
        } finally {
            foreach (array_reverse($files) as $file) {
                unlink($file);
            }
            $directories = array_unique($directories);
            usort($directories, static fn(string $left, string $right): int => strlen($right) <=> strlen($left));
            foreach ($directories as $directory) {
                rmdir($directory);
            }
        }
    }

    public function test_multilib_packages_have_architecture_specific_assessment_subjects(): void
    {
        $root = sys_get_temp_dir() . '/pra-rpm-multilib-identities-' . bin2hex(random_bytes(6));
        $directories = [$root];
        $files = [];
        try {
            foreach (['/usr/bin/rpm', '/etc/os-release', '/usr/lib/sysimage/rpm/rpmdb.sqlite', '/commands.json'] as $path) {
                $directory = dirname($root . $path);
                $missing = [];
                while (!is_dir($directory)) {
                    $missing[] = $directory;
                    $directory = dirname($directory);
                }
                foreach (array_reverse($missing) as $directory) {
                    self::assertTrue(mkdir($directory));
                    $directories[] = $directory;
                }
                $files[] = $root . $path;
                file_put_contents($root . $path, 'synthetic layout marker');
            }
            file_put_contents($root . '/etc/os-release', "ID=rhel\nVERSION_ID=10\n");
            file_put_contents($root . '/commands.json', json_encode(['commands' => [
                'rpm-packages' => [
                    'exit_code' => 0,
                    'stdout' => "php-fpm\t8.3.36-1.el10_2\tx86_64\nphp-fpm\t8.3.36-1.el10_2\ti686\n",
                ],
            ]], JSON_THROW_ON_ERROR));

            $inventory = (new RuntimeInventoryCollector(new FixtureProcessRunner($root), $root))->collect();
            self::assertSame('attempted', $inventory['package_inventory_state']);
            self::assertSame([
                ['name' => 'php-fpm', 'version' => '8.3.36-1.el10_2', 'architecture' => 'x86_64'],
                ['name' => 'php-fpm', 'version' => '8.3.36-1.el10_2', 'architecture' => 'i686'],
            ], $inventory['packages']);

            $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());
            $subjectIds = array_values(array_unique(array_column(
                array_filter(
                    $evaluation['assessments'],
                    static fn(array $assessment): bool => str_starts_with(
                        $assessment['record_id'],
                        'assessment:CVE-2026-109618:package-',
                    ),
                ),
                'subject_id',
            )));
            $expectedIds = [
                'package-' . substr(hash('sha256', "php-fpm\0" . '8.3.36-1.el10_2' . "\0" . 'x86_64'), 0, 20),
                'package-' . substr(hash('sha256', "php-fpm\0" . '8.3.36-1.el10_2' . "\0" . 'i686'), 0, 20),
            ];
            sort($subjectIds, SORT_STRING);
            sort($expectedIds, SORT_STRING);
            self::assertSame($expectedIds, $subjectIds);
        } finally {
            foreach (array_reverse($files) as $file) {
                unlink($file);
            }
            $directories = array_unique($directories);
            usort($directories, static fn(string $left, string $right): int => strlen($right) <=> strlen($left));
            foreach ($directories as $directory) {
                rmdir($directory);
            }
        }
    }

    public function test_successful_empty_rpm_query_is_a_complete_empty_package_inventory(): void
    {
        $root = sys_get_temp_dir() . '/pra-rpm-empty-' . bin2hex(random_bytes(6));
        $directories = [$root];
        $files = [];
        try {
            foreach (['/usr/bin/rpm', '/etc/os-release', '/usr/lib/sysimage/rpm/rpmdb.sqlite', '/commands.json'] as $path) {
                $directory = dirname($root . $path);
                $missing = [];
                while (!is_dir($directory)) {
                    $missing[] = $directory;
                    $directory = dirname($directory);
                }
                foreach (array_reverse($missing) as $directory) {
                    self::assertTrue(mkdir($directory));
                    $directories[] = $directory;
                }
                $files[] = $root . $path;
                file_put_contents($root . $path, 'synthetic layout marker');
            }
            file_put_contents($root . '/etc/os-release', "ID=rhel\nVERSION_ID=10\n");
            file_put_contents($root . '/commands.json', json_encode(['commands' => [
                'rpm-packages' => ['exit_code' => 0, 'stdout' => ''],
            ]], JSON_THROW_ON_ERROR));

            $inventory = (new RuntimeInventoryCollector(new FixtureProcessRunner($root), $root))->collect();
            self::assertSame('attempted', $inventory['package_inventory_state']);
            self::assertSame([], $inventory['packages']);

            $packageCoverage = array_values(array_filter(
                $inventory['coverage'],
                static fn(array $coverage): bool => $coverage['check_id'] === 'runtime.packages',
            ));
            self::assertCount(1, $packageCoverage);
            self::assertSame('attempted', $packageCoverage[0]['status']);
            self::assertNull($packageCoverage[0]['gap']);
        } finally {
            foreach (array_reverse($files) as $file) {
                unlink($file);
            }
            $directories = array_unique($directories);
            usort($directories, static fn(string $left, string $right): int => strlen($right) <=> strlen($left));
            foreach ($directories as $directory) {
                rmdir($directory);
            }
        }
    }
}
