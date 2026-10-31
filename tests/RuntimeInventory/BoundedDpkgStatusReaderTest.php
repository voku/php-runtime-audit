<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\RuntimeInventory;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use voku\PhpRuntimeAudit\RuntimeInventory\BoundedDpkgStatusReader;

final class BoundedDpkgStatusReaderTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/pra-dpkg-observation-' . bin2hex(random_bytes(8));
        self::assertTrue(mkdir($this->root . '/var/lib/dpkg', 0700, true));
    }

    protected function tearDown(): void
    {
        $file = $this->root . '/var/lib/dpkg/status';
        if (is_file($file) || is_link($file)) {
            unlink($file);
        }
        rmdir($this->root . '/var/lib/dpkg');
        rmdir($this->root . '/var/lib');
        rmdir($this->root . '/var');
        rmdir($this->root);
    }

    public function testReadsOnlyInstalledPhpMetadataIncludingLegalEmptyAndFoldedFields(): void
    {
        $contents = self::validStatus();
        file_put_contents($this->root . '/var/lib/dpkg/status', $contents);

        $observation = (new BoundedDpkgStatusReader($this->root))->observe();

        self::assertSame($contents, $observation['content']);
        self::assertSame([
            ['name' => 'php8.3-fpm', 'version' => '8.3.6-0ubuntu0.24.04.13'],
        ], $observation['packages']);
    }

    /** @return iterable<string, array{string}> */
    public static function malformedStatus(): iterable
    {
        $valid = self::validStatus();
        yield 'duplicate PHP stanza' => [$valid . "\n" . $valid];
        yield 'duplicate version' => [str_replace('Version: 8.3.6-0ubuntu0.24.04.13', "Version: 8.3.6-0ubuntu0.24.04.13\nVersion: 8.3.7", $valid)];
        yield 'absent version' => [str_replace("Version: 8.3.6-0ubuntu0.24.04.13\n", '', $valid)];
        yield 'invalid version' => [str_replace('Version: 8.3.6-0ubuntu0.24.04.13', 'Version: /unsafe', $valid)];
        yield 'unknown status' => [str_replace('Status: install ok installed', 'Status:', $valid)];
        yield 'malformed field' => [str_replace('Architecture: amd64', 'not a valid field', $valid)];
        yield 'nul byte' => [$valid . "\0"];
    }

    #[DataProvider('malformedStatus')]
    public function testRejectsAmbiguousOrMalformedStatus(string $contents): void
    {
        file_put_contents($this->root . '/var/lib/dpkg/status', $contents);
        $this->expectException(RuntimeException::class);
        (new BoundedDpkgStatusReader($this->root))->observe();
    }

    public function testRefusesSymlinkedStatus(): void
    {
        $file = $this->root . '/var/lib/dpkg/status';
        $target = $this->root . '/target';
        file_put_contents($target, self::validStatus());
        symlink($target, $file);
        try {
            $this->expectException(RuntimeException::class);
            (new BoundedDpkgStatusReader($this->root))->observe();
        } finally {
            unlink($target);
        }
    }

    public function testRefusesOversizedDpkgStatus(): void
    {
        file_put_contents($this->root . '/var/lib/dpkg/status', str_repeat('x', 8_388_609));
        $this->expectException(RuntimeException::class);
        (new BoundedDpkgStatusReader($this->root))->observe();
    }

    public function testBlockedPackageCommandExposesFileFactsWithoutVerifyingPackages(): void
    {
        file_put_contents($this->root . '/var/lib/dpkg/status', self::validStatus());
        file_put_contents($this->root . '/commands.json', '{"commands":{}}');

        $inventory = (new \voku\PhpRuntimeAudit\RuntimeInventory\RuntimeInventoryCollector(
            new \voku\PhpRuntimeAudit\RuntimeInventory\FixtureProcessRunner($this->root),
            $this->root,
            '2026-10-31T00:00:00Z',
        ))->collect();

        $facts = array_column($inventory['facts'], 'value', 'key');
        self::assertSame('unknown', $facts['packages.state']);
        self::assertSame('observed', $facts['packages.file_observation.state']);
        self::assertSame(1, $facts['packages.file_observation.package_count']);
        self::assertSame('php8.3-fpm', $facts['packages.file_observation.0.name']);
        self::assertSame('8.3.6-0ubuntu0.24.04.13', $facts['packages.file_observation.0.version']);
        self::assertSame([], $inventory['packages'], 'Local file facts cannot be promoted into verified runtime packages.');

        $this->assertCount(1, array_filter(
            $inventory['sources'],
            static fn (array $source): bool => $source['locator'] === 'file:/var/lib/dpkg/status'
                && str_starts_with((string) $source['captured_digest'], 'sha256:'),
        ));
    }

    public function testMalformedStatusRemainsUnknownWhenPackageCommandIsBlocked(): void
    {
        file_put_contents($this->root . '/var/lib/dpkg/status', self::validStatus() . "\n" . self::validStatus());
        file_put_contents($this->root . '/commands.json', '{"commands":{}}');

        $inventory = (new \voku\PhpRuntimeAudit\RuntimeInventory\RuntimeInventoryCollector(
            new \voku\PhpRuntimeAudit\RuntimeInventory\FixtureProcessRunner($this->root),
            $this->root,
            '2026-10-31T00:00:00Z',
        ))->collect();

        $facts = array_column($inventory['facts'], 'value', 'key');
        self::assertSame('unknown', $facts['packages.state']);
        self::assertSame('unknown', $facts['packages.file_observation.state']);
        self::assertSame([], $inventory['packages']);
    }

    private static function validStatus(): string
    {
        return "Package: linux-image-generic\nStatus: install ok installed\nVersion: 6.8.0\n\n"
            . "Package: php8.3-fpm\nStatus: install ok installed\nConffiles:\n /etc/php/fpm.ini 0abc\n"
            . "Version: 8.3.6-0ubuntu0.24.04.13\nArchitecture: amd64\nDescription: PHP FPM\n folded field\n\n"
            . "Package: php8.2-cli\nStatus: deinstall ok config-files\nVersion: 8.2.1\n";
    }
}
