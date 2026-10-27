<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\RuntimeInventory;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use voku\PhpRuntimeAudit\RuntimeInventory\FixtureProcessRunner;
use voku\PhpRuntimeAudit\RuntimeInventory\RuntimeInventoryCollector;

/** @phpstan-import-type RuntimeInventory from RuntimeInventoryCollector */
final class RuntimePackageProvenanceTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/pra-integrity-' . bin2hex(random_bytes(8));
        $this->copyDirectory(dirname(__DIR__) . '/fixtures/runtime/synthetic-debian-integrity', $this->root);
        unlink($this->root . '/proc/123/exe');
        self::assertTrue(symlink('../../usr/sbin/php-fpm8.2', $this->root . '/proc/123/exe'));
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->root);
    }

    public function test_synthetic_matching_local_package_and_loaded_identity_proves_only_local_integrity(): void
    {
        $inventory = $this->collect();
        $proof = $inventory['workers'][0]['package_provenance'];
        self::assertTrue($proof['verified']);
        self::assertSame('php8.2-fpm', $proof['package_name']);
        self::assertSame('8.2.35-1~deb12u1', $proof['package_version']);
        self::assertSame('/usr/sbin/php-fpm8.2', $proof['executable_path']);
        self::assertSame('local_package_database', $proof['trust_boundary']);
        self::assertNotEmpty($proof['evidence_source_ids']);
        self::assertContains('fact.worker.1.package_provenance', array_column($inventory['facts'], 'fact_id'));
    }

    /** @return iterable<string, array{string}> */
    public static function invalidEvidence(): iterable
    {
        foreach (['replaced-binary', 'replaced-loaded', 'marker-binary', 'missing-checksum', 'duplicate-checksum', 'truncated-checksum', 'symlink-checksum', 'symlink-binary', 'package-version', 'package-status', 'stat-pid', 'unsupported-distro', 'oversized-binary'] as $case) {
            yield $case => [$case];
        }
    }

    #[DataProvider('invalidEvidence')]
    public function test_missing_ambiguous_or_replaced_evidence_stays_unverified(string $case): void
    {
        $binary = $this->root . '/usr/sbin/php-fpm8.2';
        $metadata = $this->root . '/var/lib/dpkg/info/php8.2-fpm.md5sums';
        $status = $this->root . '/var/lib/dpkg/status';
        if ($case === 'replaced-binary') {
            file_put_contents($binary, 'replacement', FILE_APPEND);
        } elseif ($case === 'replaced-loaded') {
            copy($binary, $this->root . '/usr/sbin/other-fpm');
            unlink($this->root . '/proc/123/exe');
            symlink('../../usr/sbin/other-fpm', $this->root . '/proc/123/exe');
        } elseif ($case === 'marker-binary') {
            file_put_contents($binary, 'fixture executable marker');
            file_put_contents($metadata, md5_file($binary) . "  usr/sbin/php-fpm8.2\n");
        } elseif ($case === 'missing-checksum') {
            unlink($metadata);
        } elseif ($case === 'duplicate-checksum') {
            $contents = file_get_contents($metadata);
            self::assertIsString($contents);
            file_put_contents($metadata, $contents . $contents);
        } elseif ($case === 'truncated-checksum') {
            file_put_contents($metadata, str_repeat('x', 1_048_577));
        } elseif ($case === 'symlink-checksum') {
            rename($metadata, $metadata . '.actual');
            symlink($metadata . '.actual', $metadata);
        } elseif ($case === 'symlink-binary') {
            rename($binary, $binary . '.actual');
            symlink($binary . '.actual', $binary);
        } elseif ($case === 'package-version') {
            file_put_contents($status, "Package: php8.2-fpm\nStatus: install ok installed\nVersion: 8.2.34-1~deb12u1\n\n");
        } elseif ($case === 'package-status') {
            file_put_contents($status, "Package: php8.2-fpm\nStatus: deinstall ok config-files\nVersion: 8.2.35-1~deb12u1\n\n");
        } elseif ($case === 'stat-pid') {
            $stat = file_get_contents($this->root . '/proc/123/stat');
            self::assertIsString($stat);
            file_put_contents($this->root . '/proc/123/stat', preg_replace('/\A123 /', '124 ', $stat));
        } elseif ($case === 'unsupported-distro') {
            file_put_contents($this->root . '/etc/os-release', "ID=alpine\nVERSION_ID=3.23\n");
        } elseif ($case === 'oversized-binary') {
            $file = fopen($binary, 'r+');
            self::assertIsResource($file);
            ftruncate($file, 33_554_433);
            fclose($file);
        }

        self::assertFalse($this->collect()['workers'][0]['package_provenance']['verified']);
    }

    public function test_hash_budget_is_shared_across_workers(): void
    {
        $binary = $this->root . '/usr/sbin/php-fpm8.2';
        $file = fopen($binary, 'r+');
        self::assertIsResource($file);
        ftruncate($file, 4_194_304);
        fclose($file);
        file_put_contents($this->root . '/var/lib/dpkg/info/php8.2-fpm.md5sums', md5_file($binary) . "  usr/sbin/php-fpm8.2\n");
        $stat = file_get_contents($this->root . '/proc/123/stat');
        self::assertIsString($stat);
        for ($pid = 124; $pid < 139; ++$pid) {
            $this->copyDirectory($this->root . '/proc/123', $this->root . '/proc/' . $pid);
            file_put_contents($this->root . '/proc/' . $pid . '/stat', preg_replace('/\A123 /', (string) $pid . ' ', $stat));
        }
        $workers = $this->collect()['workers'];
        self::assertCount(16, $workers);
        self::assertCount(8, array_filter($workers, static fn(array $worker): bool => $worker['package_provenance']['verified']));
    }

    public function test_original_marker_fixture_cannot_prove_package_integrity(): void
    {
        $root = dirname(__DIR__) . '/fixtures/runtime/debian-fpm';
        $inventory = (new RuntimeInventoryCollector(new FixtureProcessRunner($root), $root))->collect();
        self::assertFalse($inventory['workers'][0]['package_provenance']['verified']);
    }

    /** @return RuntimeInventory */
    private function collect(): array
    {
        return (new RuntimeInventoryCollector(new FixtureProcessRunner($this->root), $this->root, '2026-10-26T00:00:00Z'))->collect();
    }

    private function copyDirectory(string $source, string $destination): void
    {
        mkdir($destination, 0777, true);
        foreach (new \DirectoryIterator($source) as $entry) {
            if ($entry->isDot()) {
                continue;
            }
            $target = $destination . '/' . $entry->getFilename();
            if ($entry->isLink()) {
                $link = readlink($entry->getPathname());
                self::assertIsString($link);
                symlink($link, $target);
            } elseif ($entry->isDir()) {
                $this->copyDirectory($entry->getPathname(), $target);
            } else {
                copy($entry->getPathname(), $target);
            }
        }
    }

    private function removeDirectory(string $directory): void
    {
        foreach (new \DirectoryIterator($directory) as $entry) {
            if ($entry->isDot()) {
                continue;
            }
            if (!$entry->isLink() && $entry->isDir()) {
                $this->removeDirectory($entry->getPathname());
            } else {
                unlink($entry->getPathname());
            }
        }
        rmdir($directory);
    }
}
