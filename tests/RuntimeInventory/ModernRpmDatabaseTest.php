<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\RuntimeInventory;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
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
            self::assertSame($known ? [['name' => 'php-fpm', 'version' => '8.3.36-1.el10_2']] : [], $inventory['packages']);
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
