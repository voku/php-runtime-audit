<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\RuntimeInventory;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use voku\PhpRuntimeAudit\RuntimeInventory\FixtureProcessRunner;
use voku\PhpRuntimeAudit\RuntimeInventory\DiscoveredPhpCommand;
use voku\PhpRuntimeAudit\RuntimeInventory\ProcessCommand;
use voku\PhpRuntimeAudit\RuntimeInventory\RuntimeInventoryCollector;

/** @phpstan-import-type RuntimeInventory from RuntimeInventoryCollector */
final class RuntimeInventoryCollectorTest extends TestCase
{
    public function test_debian_fpm_records_cli_package_and_running_worker_separately(): void
    {
        $inventory = $this->collect('debian-fpm');

        self::assertSame('debian', $inventory['distribution']);
        self::assertSame('bookworm', $inventory['distribution_codename']);
        self::assertSame('8.2.35', $inventory['runtimes'][0]['version']);
        self::assertSame('cli', $inventory['runtimes'][0]['sapi']);
        self::assertSame('8.2.35', $inventory['workers'][0]['version']);
        self::assertSame(12345, $inventory['workers'][0]['process_start_ticks_since_boot']);
        self::assertSame('php8.2-fpm', $inventory['packages'][1]['name']);
        self::assertSame('8.2.35-1~deb12u1', $inventory['packages'][1]['version']);
        self::assertSame('observed', $inventory['configuration']['session.upload_progress.enabled']['state']);
        self::assertSame('0', $inventory['configuration']['session.upload_progress.enabled']['value']);
        self::assertSame('observed', $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled']['state']);
        self::assertSame('unknown', $inventory['configuration_by_sapi']['cli']['session.upload_progress.enabled']['state']);
        self::assertSame([['name' => 'opcache', 'file' => '/etc/php/8.2/fpm/conf.d/20-opcache.ini']], $inventory['configuration']['configured_extensions']);
        self::assertSame(
            ['/etc/php/8.2/fpm/php.ini'],
            $inventory['configuration']['session.upload_progress.enabled']['files'],
        );
    }

    public function test_fpm_executable_probe_is_preserved_as_a_separate_runtime_subject(): void
    {
        $inventory = $this->collect('debian-fpm');

        self::assertCount(1, $inventory['fpm_executables']);
        self::assertSame('fpm-executable-' . substr(hash('sha256', '/usr/sbin/php-fpm8.2'), 0, 20), $inventory['fpm_executables'][0]['id']);
        self::assertSame('/usr/sbin/php-fpm8.2', $inventory['fpm_executables'][0]['binary_path']);
        self::assertSame('8.2.35', $inventory['fpm_executables'][0]['version']);
        self::assertNotSame($inventory['workers'][0]['id'], $inventory['fpm_executables'][0]['id']);
        self::assertSame('8.2.35', $this->factValue($inventory, 'runtime.fpm_executable.1.version'));
    }

    /** @return iterable<string, array{string}> */
    public static function malformedSuccessfulFpmProbeOutputs(): iterable
    {
        yield 'unrecognized output' => ['unrecognized successful FPM output'];
        yield 'valid banner followed by unexpected output' => ["PHP 8.2.35 (fpm-fcgi) (built: fixture)\nunexpected FPM output\n"];
    }

    #[DataProvider('malformedSuccessfulFpmProbeOutputs')]
    public function test_malformed_successful_inactive_fpm_probe_keeps_discovery_incomplete(string $stdout): void
    {
        $root = sys_get_temp_dir() . '/pra-fpm-probe-incomplete-' . bin2hex(random_bytes(6));
        mkdir($root . '/usr/sbin', 0777, true);
        file_put_contents($root . '/usr/sbin/php-fpm8.2', 'fixture PHP FPM executable');
        chmod($root . '/usr/sbin/php-fpm8.2', 0755);
        $commandId = ProcessCommand::Fpm82->value;
        file_put_contents($root . '/commands.json', json_encode([
            'commands' => [
                $commandId => ['exit_code' => 0, 'stdout' => $stdout],
            ],
        ], JSON_THROW_ON_ERROR));

        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-27T00:00:00Z',
                '/usr/sbin',
            ))->collect();
            $coverage = array_values(array_filter(
                $inventory['coverage'],
                static fn(array $entry): bool => $entry['check_id'] === 'runtime.discovery',
            ))[0];

            self::assertCount(1, $inventory['fpm_executables']);
            self::assertNull($inventory['fpm_executables'][0]['version']);
            self::assertTrue($this->factValue($inventory, 'runtime.discovery.incomplete'));
            self::assertTrue($this->factValue($inventory, 'runtime.discovery.fpm_probe_incomplete'));
            self::assertSame('blocked', $coverage['status']);
            self::assertStringContainsString('successful PHP FPM probes returned malformed or ambiguous runtime data', $coverage['gap'] ?? '');
        } finally {
            $this->removeTemporaryTree($root);
        }
    }

    /** @return iterable<string, array{string, string}> */
    public static function validSuccessfulFpmProbeOutputs(): iterable
    {
        yield 'PHP 5.6' => [
            "PHP 5.6.40 (fpm-fcgi) (built: Jan 23 2019 00:16:23)\nCopyright (c) 1997-2016 The PHP Group\nZend Engine v2.6.0, Copyright (c) 1998-2016 Zend Technologies\n",
            '5.6.40',
        ];
        yield 'PHP 7.4 with spaced thread mode' => [
            "PHP 7.4.33 (fpm-fcgi) (built: Sep 29 2022 11:09:22) ( NTS )\nCopyright (c) The PHP Group\nZend Engine v3.4.0, Copyright (c) Zend Technologies\n",
            '7.4.33',
        ];
        yield 'PHP 8.5' => [
            "PHP 8.5.12 (fpm-fcgi) (built: Oct 21 2026 15:49:51) (NTS)\nCopyright (c) The PHP Group\nBuilt by https://github.com/php/php-src\nZend Engine v4.5.12, Copyright (c) Zend Technologies\n    with Zend OPcache v8.5.12, Copyright (c), by Zend Technologies\n",
            '8.5.12',
        ];
    }

    #[DataProvider('validSuccessfulFpmProbeOutputs')]
    public function test_standard_successful_fpm_output_is_parsed_as_a_complete_probe(string $stdout, string $expectedVersion): void
    {
        $root = sys_get_temp_dir() . '/pra-fpm-standard-banner-' . bin2hex(random_bytes(6));
        mkdir($root . '/usr/sbin', 0777, true);
        file_put_contents($root . '/usr/sbin/php-fpm', 'fixture PHP FPM executable');
        chmod($root . '/usr/sbin/php-fpm', 0755);
        file_put_contents($root . '/commands.json', json_encode([
            'commands' => [
                ProcessCommand::FpmUsrSbin->value => ['exit_code' => 0, 'stdout' => $stdout],
            ],
        ], JSON_THROW_ON_ERROR));

        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-27T00:00:00Z',
                '/usr/sbin',
            ))->collect();

            self::assertCount(1, $inventory['fpm_executables']);
            self::assertSame($expectedVersion, $inventory['fpm_executables'][0]['version']);
            self::assertFalse($this->factValue($inventory, 'runtime.discovery.fpm_probe_incomplete'));
        } finally {
            $this->removeTemporaryTree($root);
        }
    }

    public function test_conflicting_successful_fpm_version_banners_keep_discovery_incomplete(): void
    {
        $root = sys_get_temp_dir() . '/pra-fpm-conflicting-banner-' . bin2hex(random_bytes(6));
        mkdir($root . '/usr/sbin', 0777, true);
        file_put_contents($root . '/usr/sbin/php-fpm8.2', 'fixture PHP FPM executable');
        chmod($root . '/usr/sbin/php-fpm8.2', 0755);
        $commandId = ProcessCommand::Fpm82->value;
        file_put_contents($root . '/commands.json', json_encode([
            'commands' => [
                $commandId => ['exit_code' => 0, 'stdout' => "PHP 8.2.35 (fpm-fcgi)\nPHP 8.3.36 (fpm-fcgi)\n"],
            ],
        ], JSON_THROW_ON_ERROR));

        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-27T00:00:00Z',
                '/usr/sbin',
            ))->collect();
            $coverage = array_values(array_filter(
                $inventory['coverage'],
                static fn(array $entry): bool => $entry['check_id'] === 'runtime.discovery',
            ))[0];

            self::assertCount(1, $inventory['fpm_executables']);
            self::assertNull($inventory['fpm_executables'][0]['version']);
            self::assertTrue($this->factValue($inventory, 'runtime.discovery.incomplete'));
            self::assertTrue($this->factValue($inventory, 'runtime.discovery.fpm_probe_incomplete'));
            self::assertSame('blocked', $coverage['status']);
            self::assertStringContainsString('successful PHP FPM probes returned malformed or ambiguous runtime data', $coverage['gap'] ?? '');
        } finally {
            $this->removeTemporaryTree($root);
        }
    }

    public function test_cli_version_probes_use_php_5_3_compatible_array_syntax(): void
    {
        $fixedProbe = ProcessCommand::PhpUsrBin->argv()[3];
        $discoveredProbe = DiscoveredPhpCommand::fromPath('/usr/bin/php5.3', 'cli')->argv()[3];

        self::assertSame($fixedProbe, $discoveredProbe);
        self::assertStringContainsString('json_encode(array(', $fixedProbe);
        self::assertStringNotContainsString('[', $fixedProbe);
        self::assertStringNotContainsString(']', $fixedProbe);
    }

    public function test_safe_fixed_php_symlink_is_probed_when_no_versioned_command_exists(): void
    {
        $root = sys_get_temp_dir() . '/pra-fixed-php-link-' . bin2hex(random_bytes(6));
        mkdir($root . '/usr/bin', 0777, true);
        file_put_contents($root . '/usr/bin/php-cli', 'fixture PHP executable');
        self::assertTrue(symlink('php-cli', $root . '/usr/bin/php'));
        file_put_contents($root . '/commands.json', json_encode([
            'commands' => [
                'php-usr-bin' => ['exit_code' => 0, 'stdout' => '{"version":"8.2.35","sapi":"cli","extensions":[]}'],
            ],
        ], JSON_THROW_ON_ERROR));

        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-27T00:00:00Z',
                '/usr/bin',
            ))->collect();

            self::assertCount(1, $inventory['runtimes']);
            self::assertSame('/usr/bin/php', $inventory['runtimes'][0]['binary_path']);
            self::assertSame('8.2.35', $inventory['runtimes'][0]['version']);
            self::assertFalse($this->factValue($inventory, 'runtime.discovery.incomplete'));
        } finally {
            $this->removeTemporaryTree($root);
        }
    }

    public function test_fixed_php_symlink_to_versioned_binary_uses_one_runtime_probe(): void
    {
        $root = sys_get_temp_dir() . '/pra-fixed-php-versioned-link-' . bin2hex(random_bytes(6));
        mkdir($root . '/usr/bin', 0777, true);
        file_put_contents($root . '/usr/bin/php8.2', 'fixture PHP executable');
        self::assertTrue(symlink('php8.2', $root . '/usr/bin/php'));
        file_put_contents($root . '/commands.json', json_encode([
            'commands' => [
                ProcessCommand::Php82->value => ['exit_code' => 0, 'stdout' => '{"version":"8.2.35","sapi":"cli","extensions":[]}'],
            ],
        ], JSON_THROW_ON_ERROR));

        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-27T00:00:00Z',
                '/usr/bin',
            ))->collect();

            self::assertCount(1, $inventory['runtimes']);
            self::assertSame('/usr/bin/php8.2', $inventory['runtimes'][0]['binary_path']);
            self::assertFalse($this->factValue($inventory, 'runtime.discovery.incomplete'));
            self::assertNull($this->factValue($inventory, 'command.php-usr-bin.result'));
        } finally {
            $this->removeTemporaryTree($root);
        }
    }

    public function test_bin_and_sbin_path_aliases_to_scanned_runtime_directories_do_not_block_discovery(): void
    {
        $root = sys_get_temp_dir() . '/pra-standard-path-aliases-' . bin2hex(random_bytes(6));
        mkdir($root . '/usr/bin', 0777, true);
        mkdir($root . '/usr/sbin', 0777, true);
        file_put_contents($root . '/usr/bin/php8.2', 'fixture PHP CLI');
        self::assertTrue(symlink('usr/bin', $root . '/bin'));
        self::assertTrue(symlink('usr/sbin', $root . '/sbin'));
        $commandId = ProcessCommand::Php82->value;
        file_put_contents($root . '/commands.json', json_encode([
            'commands' => [
                $commandId => ['exit_code' => 0, 'stdout' => '{"version":"8.2.35","sapi":"cli","extensions":[]}'],
            ],
        ], JSON_THROW_ON_ERROR));

        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-27T00:00:00Z',
                '/bin:/sbin',
            ))->collect();

            self::assertCount(1, $inventory['runtimes']);
            self::assertSame('/usr/bin/php8.2', $inventory['runtimes'][0]['binary_path']);
            self::assertFalse($this->factValue($inventory, 'runtime.discovery.incomplete'));
            self::assertSame('attempted', $inventory['coverage'][4]['status']);
        } finally {
            $this->removeTemporaryTree($root);
        }
    }

    public function test_unknown_path_directory_symlink_still_blocks_discovery(): void
    {
        $root = sys_get_temp_dir() . '/pra-unknown-path-alias-' . bin2hex(random_bytes(6));
        mkdir($root . '/opt/php/bin', 0777, true);
        self::assertTrue(symlink('opt/php/bin', $root . '/bin'));
        file_put_contents($root . '/commands.json', '{"commands":{}}');

        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-27T00:00:00Z',
                '/bin',
            ))->collect();

            self::assertTrue($this->factValue($inventory, 'runtime.discovery.incomplete'));
            self::assertSame('blocked', $inventory['coverage'][4]['status']);
        } finally {
            $this->removeTemporaryTree($root);
        }
    }

    public function test_fixed_php_symlink_outside_runtime_directories_is_not_probed(): void
    {
        $root = sys_get_temp_dir() . '/pra-unsafe-php-link-' . bin2hex(random_bytes(6));
        mkdir($root . '/usr/bin', 0777, true);
        mkdir($root . '/etc', 0777, true);
        file_put_contents($root . '/etc/php-source', 'must not be probed');
        self::assertTrue(symlink('../../etc/php-source', $root . '/usr/bin/php'));
        file_put_contents($root . '/commands.json', json_encode([
            'commands' => [
                'php-usr-bin' => ['exit_code' => 0, 'stdout' => '{"version":"8.2.35","sapi":"cli","extensions":[]}'],
            ],
        ], JSON_THROW_ON_ERROR));

        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-27T00:00:00Z',
                '/usr/bin',
            ))->collect();

            self::assertSame([], $inventory['runtimes']);
            self::assertTrue($this->factValue($inventory, 'runtime.discovery.incomplete'));
        } finally {
            $this->removeTemporaryTree($root);
        }
    }

    public function test_malformed_php_runtime_names_are_not_probed_and_block_discovery_coverage(): void
    {
        $root = sys_get_temp_dir() . '/pra-malformed-php-name-' . bin2hex(random_bytes(6));
        mkdir($root . '/usr/bin', 0777, true);
        file_put_contents($root . '/usr/bin/php7..4', 'malformed PHP executable name');
        file_put_contents($root . '/commands.json', '{"commands":{}}');

        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-27T00:00:00Z',
                '/usr/bin',
            ))->collect();

            self::assertSame([], $inventory['runtimes']);
            self::assertTrue($this->factValue($inventory, 'runtime.discovery.incomplete'));
            $coverage = array_values(array_filter(
                $inventory['coverage'],
                static fn(array $entry): bool => $entry['check_id'] === 'runtime.discovery',
            ));
            self::assertCount(1, $coverage);
            self::assertSame('blocked', $coverage[0]['status']);
            self::assertStringNotContainsString('command.discovered-', json_encode($inventory['facts'], JSON_THROW_ON_ERROR));
        } finally {
            $this->removeTemporaryTree($root);
        }
    }

    /** @return iterable<string, array{string}> */
    public static function malformedSuccessfulCliProbeOutputs(): iterable
    {
        yield 'malformed JSON' => ['not-json'];
        yield 'duplicate JSON key' => ['{"version":"7.4.33","version":"7.4.34","sapi":"cli","extensions":[]}'];
    }

    #[DataProvider('malformedSuccessfulCliProbeOutputs')]
    public function test_malformed_successful_cli_probe_keeps_mixed_discovery_incomplete(string $invalidOutput): void
    {
        $root = sys_get_temp_dir() . '/pra-cli-probe-incomplete-' . bin2hex(random_bytes(6));
        mkdir($root . '/usr/bin', 0777, true);
        file_put_contents($root . '/usr/bin/php', 'fixture PHP CLI');
        file_put_contents($root . '/usr/bin/php7.4', 'fixture PHP 7.4 CLI');
        $invalidCommandId = DiscoveredPhpCommand::fromPath('/usr/bin/php7.4', 'cli')->id();
        file_put_contents($root . '/commands.json', json_encode([
            'commands' => [
                ProcessCommand::PhpUsrBin->value => [
                    'exit_code' => 0,
                    'stdout' => '{"version":"8.2.35","sapi":"cli","extensions":[]}',
                ],
                $invalidCommandId => ['exit_code' => 0, 'stdout' => $invalidOutput],
            ],
        ], JSON_THROW_ON_ERROR));

        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-27T00:00:00Z',
                '/usr/bin',
            ))->collect();
            $coverage = array_values(array_filter(
                $inventory['coverage'],
                static fn(array $entry): bool => $entry['check_id'] === 'runtime.discovery',
            ))[0];

            self::assertCount(1, $inventory['runtimes']);
            self::assertSame('/usr/bin/php', $inventory['runtimes'][0]['binary_path']);
            self::assertTrue($this->factValue($inventory, 'runtime.discovery.incomplete'));
            self::assertTrue($this->factValue($inventory, 'runtime.discovery.cli_probe_incomplete'));
            self::assertSame('blocked', $coverage['status']);
            self::assertStringContainsString('successful PHP CLI probes returned malformed or ambiguous runtime data', $coverage['gap'] ?? '');
        } finally {
            $this->removeTemporaryTree($root);
        }
    }

    public function test_legacy_cli_installations_are_discovered_as_separate_versioned_runtimes(): void
    {
        $root = sys_get_temp_dir() . '/pra-legacy-cli-' . bin2hex(random_bytes(6));
        mkdir($root . '/usr/bin', 0777, true);
        mkdir($root . '/var/lib/dpkg', 0777, true);
        file_put_contents($root . '/usr/bin/php5.6', 'fixture PHP 5.6');
        file_put_contents($root . '/usr/bin/php7.4', 'fixture PHP 7.4');
        file_put_contents($root . '/usr/bin/dpkg-query', 'fixture package query');
        file_put_contents($root . '/var/lib/dpkg/status', "Package: php5.6-cli\nStatus: install ok installed\n\nPackage: php7.4-cli\nStatus: install ok installed\n");
        $php56 = DiscoveredPhpCommand::fromPath('/usr/bin/php5.6', 'cli')->id();
        $php74 = DiscoveredPhpCommand::fromPath('/usr/bin/php7.4', 'cli')->id();
        file_put_contents($root . '/commands.json', json_encode([
            'commands' => [
                $php56 => ['exit_code' => 0, 'stdout' => '{"version":"5.6.40","sapi":"cli","extensions":[]}'],
                $php74 => ['exit_code' => 0, 'stdout' => '{"version":"7.4.33","sapi":"cli","extensions":[]}'],
                'dpkg-packages' => ['exit_code' => 0, 'stdout' => "php5.6-cli\t5.6.40-0+deb.sury.org+1\tinstall ok installed\nphp7.4-cli\t7.4.33-1+deb.sury.org+1\tinstall ok installed\n"],
            ],
        ], JSON_THROW_ON_ERROR));
        symlink('/usr/bin/php5.6', $root . '/usr/bin/php8.1');

        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-27T00:00:00Z',
            ))->collect();

            $runtimes = [];
            foreach ($inventory['runtimes'] as $runtime) {
                $runtimes[$runtime['binary_path']] = $runtime;
            }
            self::assertSame('5.6.40', $runtimes['/usr/bin/php5.6']['version']);
            self::assertSame('7.4.33', $runtimes['/usr/bin/php7.4']['version']);
            self::assertNotSame($runtimes['/usr/bin/php5.6']['id'], $runtimes['/usr/bin/php7.4']['id']);
            self::assertCount(2, $inventory['packages']);
            self::assertTrue($this->factValue($inventory, 'runtime.discovery.incomplete'));
            self::assertSame('blocked', $inventory['coverage'][4]['status']);
            self::assertStringContainsString('safely', is_string($inventory['coverage'][4]['gap']) ? $inventory['coverage'][4]['gap'] : '');
        } finally {
            $this->removeTemporaryTree($root);
        }
    }

    public function test_versioned_cli_candidate_in_custom_path_is_recorded_without_execution(): void
    {
        $root = sys_get_temp_dir() . '/pra-path-cli-' . bin2hex(random_bytes(6));
        mkdir($root . '/opt/php74/bin', 0777, true);
        file_put_contents($root . '/opt/php74/bin/php7.4', 'fixture PHP 7.4');
        file_put_contents($root . '/commands.json', '{"commands":{}}');

        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-27T00:00:00Z',
                '/opt/php74/bin',
            ))->collect();

            $candidate = $this->factValue($inventory, 'runtime.discovery.path_candidate.1');
            self::assertSame([], $inventory['runtimes']);
            self::assertIsArray($candidate);
            self::assertSame('/opt/php74/bin/php7.4', $candidate['path']);
            self::assertSame('7.4', $candidate['version_hint']);
            self::assertSame('not_attempted_untrusted_path', $candidate['execution']);
            self::assertTrue($this->factValue($inventory, 'runtime.discovery.incomplete'));
            self::assertSame('blocked', $inventory['coverage'][4]['status']);
        } finally {
            unlink($root . '/commands.json');
            unlink($root . '/opt/php74/bin/php7.4');
            rmdir($root . '/opt/php74/bin');
            rmdir($root . '/opt/php74');
            rmdir($root . '/opt');
            rmdir($root);
        }
    }

    public function test_relative_path_entry_is_rejected_and_reported_as_a_discovery_gap(): void
    {
        $root = sys_get_temp_dir() . '/pra-path-invalid-' . bin2hex(random_bytes(6));
        mkdir($root . '/opt/php74/bin', 0777, true);
        file_put_contents($root . '/opt/php74/bin/php7.4', 'must not be executed');
        file_put_contents($root . '/commands.json', '{"commands":{}}');

        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-27T00:00:00Z',
                '../opt/php74/bin',
            ))->collect();

            self::assertSame([], $inventory['runtimes']);
            self::assertTrue($this->factValue($inventory, 'runtime.discovery.incomplete'));
            self::assertSame('blocked', $inventory["coverage"][4]['status']);
        } finally {
            unlink($root . '/commands.json');
            unlink($root . '/opt/php74/bin/php7.4');
            rmdir($root . '/opt/php74/bin');
            rmdir($root . '/opt/php74');
            rmdir($root . '/opt');
            rmdir($root);
        }
    }

    public function test_package_record_limit_marks_inventory_coverage_incomplete(): void
    {
        $root = sys_get_temp_dir() . '/pra-package-cap-' . bin2hex(random_bytes(6));
        mkdir($root . '/usr/bin', 0777, true);
        mkdir($root . '/var/lib/dpkg', 0777, true);
        file_put_contents($root . '/usr/bin/dpkg-query', 'fixture package query');
        file_put_contents($root . '/var/lib/dpkg/status', 'fixture package status');
        $lines = [];
        for ($index = 0; $index < 257; ++$index) {
            $lines[] = 'php' . $index . '-cli' . "\t" . '7.4.33-' . $index . "\tinstall ok installed";
        }
        file_put_contents($root . '/commands.json', json_encode([
            'commands' => ['dpkg-packages' => ['exit_code' => 0, 'stdout' => implode("\n", $lines) . "\n"]],
        ], JSON_THROW_ON_ERROR));

        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-27T00:00:00Z',
                '',
            ))->collect();
            $packageCoverage = array_values(array_filter(
                $inventory['coverage'],
                static fn(array $coverage): bool => $coverage['check_id'] === 'runtime.packages',
            ))[0];

            self::assertCount(256, $inventory['packages']);
            self::assertSame(257, $this->factValue($inventory, 'packages.inventory_count'));
            self::assertTrue($this->factValue($inventory, 'packages.truncated'));
            self::assertSame('blocked', $packageCoverage['status']);
            self::assertStringContainsString('omitted package subjects remain unknown', $packageCoverage['gap'] ?? '');
        } finally {
            unlink($root . '/commands.json');
            unlink($root . '/var/lib/dpkg/status');
            unlink($root . '/usr/bin/dpkg-query');
            rmdir($root . '/var/lib/dpkg');
            rmdir($root . '/var/lib');
            rmdir($root . '/var');
            rmdir($root . '/usr/bin');
            rmdir($root . '/usr');
            rmdir($root);
        }
    }

    public function test_discovered_runtime_command_rejects_paths_outside_approved_roots(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        DiscoveredPhpCommand::fromPath('/usr/bin/../tmp/php7.4', 'cli');
    }

    public function test_discovered_runtime_command_cannot_be_created_for_a_custom_path_directory(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        DiscoveredPhpCommand::fromPath('/opt/php74/bin/php7.4', 'cli');
    }

    public function test_runtime_command_discovery_reports_its_command_limit(): void
    {
        $root = sys_get_temp_dir() . '/pra-runtime-cap-' . bin2hex(random_bytes(6));
        mkdir($root . '/usr/bin', 0777, true);
        for ($index = 0; $index < 130; ++$index) {
            file_put_contents($root . '/usr/bin/php5.' . $index, 'fixture PHP executable');
        }
        file_put_contents($root . '/commands.json', '{"commands":{}}');
        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-27T00:00:00Z',
            ))->collect();

            self::assertTrue($this->factValue($inventory, 'runtime.discovery.truncated'));
            $coverage = array_values(array_filter(
                $inventory['coverage'],
                static fn(array $check): bool => $check['check_id'] === 'runtime.discovery',
            ));
            self::assertCount(1, $coverage);
            self::assertSame('blocked', $coverage[0]['status']);
            self::assertStringContainsString('limit', strtolower(is_string($coverage[0]['gap']) ? $coverage[0]['gap'] : ''));
        } finally {
            $this->removeTemporaryTree($root);
        }
    }

    public function test_absent_configuration_and_worker_evidence_remain_unknown(): void
    {
        $inventory = $this->collect('container-fpm');

        self::assertTrue($inventory['container']);
        self::assertSame('unknown', $inventory['configuration']['session.upload_progress.enabled']['state']);
        self::assertNull($inventory['configuration']['session.upload_progress.enabled']['value']);
        self::assertSame('unknown', $inventory['configuration']['session.serialize_handler']['state']);
        self::assertSame('unknown', $inventory['configuration_by_sapi']['fpm']['session.serialize_handler']['state']);
        self::assertNull($inventory['runtimes'][0]['extensions']);
        self::assertNull($inventory['configuration']['configured_extensions']);
        self::assertSame(12350, $inventory['workers'][0]['process_start_ticks_since_boot']);
        self::assertSame('blocked', $inventory['coverage'][3]['status']);
        self::assertNotNull($inventory['coverage'][3]['gap']);
        self::assertStringContainsString('configuration files', $inventory['coverage'][3]['gap']);
    }

    public function test_duplicate_and_hostile_process_output_does_not_become_runtime_evidence(): void
    {
        $inventory = $this->collect('hostile-output');

        self::assertSame([], $inventory['runtimes']);
        self::assertNull($inventory['workers'][0]['version']);
        self::assertSame('/usr/sbin/php-fpm8.2', $inventory['workers'][0]['executable_path']);
    }

    public function test_inconsistent_proc_identity_does_not_resolve_a_running_fpm_version(): void
    {
        $inventory = $this->collect('alpine-fpm-mismatched-process');
        $workerState = array_values(array_filter(
            $inventory['facts'],
            static fn(array $fact): bool => $fact['key'] === 'workers.state',
        ));

        self::assertSame('php-fpm82', $inventory['workers'][0]['process_name']);
        self::assertNull($inventory['workers'][0]['executable_path']);
        self::assertNull($inventory['workers'][0]['version']);
        self::assertNull($inventory['workers'][0]['process_start_ticks_since_boot']);
        self::assertCount(1, $workerState);
        self::assertSame('partial', $workerState[0]['value']);
        self::assertSame('attempted', $inventory['coverage'][2]['status']);
        self::assertNotNull($inventory['coverage'][2]['gap']);
    }

    public function test_versioned_process_name_must_match_the_fpm_executable(): void
    {
        $inventory = $this->collect('debian-fpm-process-executable-mismatch');

        self::assertSame('php-fpm8.3', $inventory['workers'][0]['process_name']);
        self::assertNull($inventory['workers'][0]['executable_path']);
        self::assertNull($inventory['workers'][0]['version']);
        self::assertNull($inventory['workers'][0]['process_start_ticks_since_boot']);
        self::assertSame('partial', $this->factValue($inventory, 'workers.state'));
        self::assertNotNull($inventory['coverage'][2]['gap']);
    }

    public function test_malformed_cli_extension_list_remains_unknown_without_discarding_version(): void
    {
        $root = sys_get_temp_dir() . '/pra-runtime-' . bin2hex(random_bytes(6));
        mkdir($root . '/usr/bin', 0777, true);
        file_put_contents($root . '/usr/bin/php', 'fixture executable');
        file_put_contents($root . '/commands.json', json_encode([
            'commands' => [
                'php-usr-bin' => [
                    'exit_code' => 0,
                    'stdout' => '{"version":"8.2.35","sapi":"cli","extensions":["Core",7]}',
                ],
            ],
        ], JSON_THROW_ON_ERROR));

        try {
            $inventory = (new RuntimeInventoryCollector(new FixtureProcessRunner($root), $root, '2026-10-25T00:00:00Z'))->collect();
            $coverage = array_values(array_filter(
                $inventory['coverage'],
                static fn(array $entry): bool => $entry['check_id'] === 'runtime.discovery',
            ))[0];

            self::assertSame('8.2.35', $inventory['runtimes'][0]['version']);
            self::assertNull($inventory['runtimes'][0]['extensions']);
            self::assertTrue($this->factValue($inventory, 'runtime.discovery.incomplete'));
            self::assertTrue($this->factValue($inventory, 'runtime.discovery.cli_probe_incomplete'));
            self::assertSame('blocked', $coverage['status']);
            self::assertStringContainsString('successful PHP CLI probes returned malformed or ambiguous runtime data', $coverage['gap'] ?? '');
        } finally {
            unlink($root . '/commands.json');
            unlink($root . '/usr/bin/php');
            rmdir($root . '/usr/bin');
            rmdir($root . '/usr');
            self::assertSame(['.', '..'], scandir($root));
            rmdir($root);
        }
    }

    public function test_apache_mapping_reports_loaded_module_and_deleted_state_without_inventing_version(): void
    {
        $inventory = $this->collect('ubuntu-apache');

        self::assertSame('apache', $inventory['workers'][0]['kind']);
        self::assertSame(['/usr/lib/apache2/modules/libphp8.3.so'], $inventory['workers'][0]['apache_php_modules']);
        self::assertFalse($inventory['workers'][0]['apache_php_module_deleted']);
        self::assertNull($inventory['workers'][0]['version']);
        self::assertSame('8.3.6-0ubuntu0.24.04.13', $inventory['packages'][1]['version']);
        self::assertSame(
            '/etc/php/8.3/apache2',
            $inventory['configuration_by_sapi']['apache2']['session.upload_progress.enabled']['observations'][0]['configuration_root'],
        );
    }

    public function test_apache_module_deleted_paths_are_recorded_individually(): void
    {
        $fixtureRoot = dirname(__DIR__) . '/fixtures/runtime/ubuntu-apache';
        $root = sys_get_temp_dir() . '/pra-apache-module-deleted-' . bin2hex(random_bytes(6));
        $this->copyDirectory($fixtureRoot, $root);
        $mapsPath = $root . '/proc/456/maps';
        $maps = file_get_contents($mapsPath);
        self::assertIsString($maps);
        file_put_contents(
            $mapsPath,
            $maps . "7f000100-7f001000 r-xp 00000000 08:01 12346 /usr/lib/apache2/modules/libphp8.2.so (deleted)\n",
        );

        try {
            $inventory = (new RuntimeInventoryCollector(
                new FixtureProcessRunner($root),
                $root,
                '2026-10-25T00:00:00Z',
            ))->collect();

            self::assertSame(
                ['/usr/lib/apache2/modules/libphp8.2.so', '/usr/lib/apache2/modules/libphp8.3.so'],
                $inventory['workers'][0]['apache_php_modules'],
            );
            self::assertTrue($inventory['workers'][0]['apache_php_module_deleted']);
            self::assertSame(
                ['/usr/lib/apache2/modules/libphp8.2.so'],
                $inventory['workers'][0]['apache_php_module_deleted_paths'],
            );
            self::assertSame(
                ['/usr/lib/apache2/modules/libphp8.2.so'],
                $this->factValue($inventory, 'worker.1.apache_php_module_deleted_paths'),
            );
        } finally {
            $this->removeTemporaryTree($root);
        }
    }

    public function test_config_file_discovery_is_bounded_and_does_not_follow_symlinked_directories(): void
    {
        $root = sys_get_temp_dir() . '/pra-runtime-' . bin2hex(random_bytes(6));
        mkdir($root . '/etc/php/8.2/fpm/conf.d', 0777, true);
        mkdir($root . '/outside', 0777, true);
        file_put_contents($root . '/outside/zz-escaped.ini', "session.upload_progress.enabled=1\n");
        symlink($root . '/outside', $root . '/etc/php/8.2/fpm/conf.d/external');
        file_put_contents($root . '/etc/php/8.2/fpm/php.ini', "session.upload_progress.enabled=0\n");
        file_put_contents($root . '/commands.json', '{"commands":{}}');

        try {
            $inventory = (new RuntimeInventoryCollector(new FixtureProcessRunner($root), $root, '2026-10-25T00:00:00Z'))->collect();
            self::assertSame('unknown', $inventory['configuration']['session.upload_progress.enabled']['state']);
            self::assertNull($inventory['configuration']['session.upload_progress.enabled']['value']);
            self::assertSame(['/etc/php/8.2/fpm/php.ini'], $inventory['configuration']['session.upload_progress.enabled']['files']);
            self::assertSame('blocked', $inventory['coverage'][3]['status']);
            self::assertNotNull($inventory['coverage'][3]['gap']);
            self::assertStringContainsString('symlinked files remain unknown', $inventory['coverage'][3]['gap']);
        } finally {
            unlink($root . '/etc/php/8.2/fpm/conf.d/external');
            unlink($root . '/etc/php/8.2/fpm/php.ini');
            unlink($root . '/outside/zz-escaped.ini');
            rmdir($root . '/etc/php/8.2/fpm/conf.d');
            rmdir($root . '/etc/php/8.2/fpm');
            rmdir($root . '/etc/php/8.2');
            rmdir($root . '/etc/php');
            rmdir($root . '/etc');
            rmdir($root . '/outside');
            unlink($root . '/commands.json');
            rmdir($root);
        }
    }

    public function test_oversized_relevant_configuration_file_keeps_settings_unknown(): void
    {
        $root = sys_get_temp_dir() . '/pra-runtime-' . bin2hex(random_bytes(6));
        $configurationDirectory = $root . '/etc/php/8.2/fpm';
        mkdir($configurationDirectory . '/conf.d', 0777, true);
        file_put_contents($configurationDirectory . '/php.ini', "session.upload_progress.enabled=0\n");
        file_put_contents(
            $configurationDirectory . '/conf.d/99-oversized.ini',
            "session.upload_progress.enabled=1\n" . str_repeat(';', 262_145),
        );
        file_put_contents($root . '/commands.json', '{"commands":{}}');

        try {
            $inventory = (new RuntimeInventoryCollector(new FixtureProcessRunner($root), $root, '2026-10-25T00:00:00Z'))->collect();

            self::assertSame('unknown', $inventory['configuration']['session.upload_progress.enabled']['state']);
            self::assertSame('unknown', $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled']['state']);
            self::assertNull($inventory['configuration']['configured_extensions']);
            self::assertSame('blocked', $inventory['coverage'][3]['status']);
            self::assertNotNull($inventory['coverage'][3]['gap']);
            self::assertStringContainsString('bounded or incomplete', $inventory['coverage'][3]['gap']);
        } finally {
            unlink($configurationDirectory . '/conf.d/99-oversized.ini');
            unlink($configurationDirectory . '/php.ini');
            rmdir($configurationDirectory . '/conf.d');
            rmdir($configurationDirectory);
            $versionDirectory = dirname($configurationDirectory);
            $phpDirectory = dirname($versionDirectory);
            $etcDirectory = dirname($phpDirectory);
            rmdir($versionDirectory);
            rmdir($phpDirectory);
            rmdir($etcDirectory);
            unlink($root . '/commands.json');
            rmdir($root);
        }
    }

    public function test_rhel_php_fpm_pool_and_shared_php_d_fragments_are_discovered(): void
    {
        $inventory = $this->collect('rhel10-fpm-pool-override');
        $uploadProgress = $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled'];
        $serializeHandler = $inventory['configuration_by_sapi']['fpm']['session.serialize_handler'];

        self::assertSame('conflict', $uploadProgress['state']);
        self::assertSame('conflict', $serializeHandler['state']);
        self::assertContains('/etc/php-fpm.d/www.conf', $uploadProgress['files']);
        self::assertContains(
            [
                'value' => '1',
                'file' => '/etc/php-fpm.d/www.conf',
                'context' => 'pool:www',
                'configuration_root' => '/etc',
            ],
            $uploadProgress['observations'],
        );
        self::assertContains('/etc/php.d/20-base.ini', $inventory['configuration']['post_max_size']['files']);
        self::assertSame('observed', $inventory['configuration_by_sapi']['fpm']['post_max_size']['state']);
        self::assertSame('attempted', $inventory['coverage'][3]['status']);
        self::assertNull($inventory['coverage'][3]['gap']);
    }

    public function test_capped_configuration_discovery_keeps_partial_settings_unknown(): void
    {
        $root = sys_get_temp_dir() . '/pra-runtime-' . bin2hex(random_bytes(6));
        $configurationDirectory = $root . '/etc/php/8.2/fpm';
        mkdir($configurationDirectory . '/conf.d', 0777, true);
        file_put_contents($configurationDirectory . '/php.ini', "session.upload_progress.enabled=0\n");
        for ($index = 0; $index < 70; ++$index) {
            file_put_contents(
                $configurationDirectory . '/conf.d/' . sprintf('%02d-extension-%d.ini', $index, $index),
                'extension=fixture' . $index . ".so\n",
            );
        }
        file_put_contents($root . '/commands.json', '{"commands":{}}');

        try {
            $inventory = (new RuntimeInventoryCollector(new FixtureProcessRunner($root), $root, '2026-10-25T00:00:00Z'))->collect();

            self::assertSame('unknown', $inventory['configuration']['session.upload_progress.enabled']['state']);
            self::assertSame('unknown', $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled']['state']);
            self::assertNull($inventory['configuration']['configured_extensions']);
            self::assertSame('blocked', $inventory['coverage'][3]['status']);
            self::assertNotNull($inventory['coverage'][3]['gap']);
            self::assertStringContainsString('bounded or incomplete', $inventory['coverage'][3]['gap']);
        } finally {
            foreach (glob($configurationDirectory . '/conf.d/*.ini') ?: [] as $file) {
                unlink($file);
            }
            rmdir($configurationDirectory . '/conf.d');
            unlink($configurationDirectory . '/php.ini');
            rmdir($configurationDirectory);
            $versionDirectory = dirname($configurationDirectory);
            $phpDirectory = dirname($versionDirectory);
            $etcDirectory = dirname($phpDirectory);
            rmdir($versionDirectory);
            rmdir($phpDirectory);
            rmdir($etcDirectory);
            unlink($root . '/commands.json');
            rmdir($root);
        }
    }

    public function test_configured_extension_count_is_bounded_per_file(): void
    {
        $root = sys_get_temp_dir() . '/pra-runtime-extension-file-cap-' . bin2hex(random_bytes(6));
        $configurationDirectory = $root . '/etc/php/8.2/fpm/conf.d';
        mkdir($configurationDirectory, 0777, true);
        $lines = [];
        for ($index = 0; $index < 600; ++$index) {
            $lines[] = 'extension=fixture' . $index . ".so\n";
        }
        file_put_contents($configurationDirectory . '/20-many-extensions.ini', implode('', $lines));
        file_put_contents($root . '/commands.json', '{"commands":{}}');

        try {
            $inventory = (new RuntimeInventoryCollector(new FixtureProcessRunner($root), $root, '2026-10-27T00:00:00Z'))->collect();

            self::assertNull($inventory['configuration']['configured_extensions']);
            self::assertSame('unknown', $inventory['configuration']['session.upload_progress.enabled']['state']);
            self::assertSame('blocked', $inventory['coverage'][3]['status']);
            self::assertStringContainsString('bounded or incomplete', $inventory['coverage'][3]['gap'] ?? '');
        } finally {
            $this->removeTemporaryTree($root);
        }
    }

    public function test_configured_extension_count_is_bounded_across_files(): void
    {
        $root = sys_get_temp_dir() . '/pra-runtime-extension-total-cap-' . bin2hex(random_bytes(6));
        $configurationDirectory = $root . '/etc/php/8.2/fpm/conf.d';
        mkdir($configurationDirectory, 0777, true);
        for ($fileIndex = 0; $fileIndex < 9; ++$fileIndex) {
            $lines = [];
            for ($extensionIndex = 0; $extensionIndex < 64; ++$extensionIndex) {
                $index = ($fileIndex * 64) + $extensionIndex;
                $lines[] = 'extension=fixture' . $index . ".so\n";
            }
            file_put_contents($configurationDirectory . '/' . sprintf('%02d-many-extensions.ini', $fileIndex), implode('', $lines));
        }
        file_put_contents($root . '/commands.json', '{"commands":{}}');

        try {
            $inventory = (new RuntimeInventoryCollector(new FixtureProcessRunner($root), $root, '2026-10-27T00:00:00Z'))->collect();

            self::assertNull($inventory['configuration']['configured_extensions']);
            self::assertSame('unknown', $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled']['state']);
            self::assertSame('blocked', $inventory['coverage'][3]['status']);
            self::assertStringContainsString('bounded or incomplete', $inventory['coverage'][3]['gap'] ?? '');
        } finally {
            $this->removeTemporaryTree($root);
        }
    }

    public function test_inaccessible_proc_entries_do_not_become_a_claim_that_no_web_worker_exists(): void
    {
        $root = sys_get_temp_dir() . '/pra-runtime-' . bin2hex(random_bytes(6));
        mkdir($root . '/proc/123', 0777, true);
        file_put_contents($root . '/commands.json', '{"commands":{}}');
        symlink('/etc/hostname', $root . '/proc/123/comm');

        try {
            $inventory = (new RuntimeInventoryCollector(new FixtureProcessRunner($root), $root, '2026-10-25T00:00:00Z'))->collect();
            $workerState = array_values(array_filter(
                $inventory['facts'],
                static fn(array $fact): bool => $fact['key'] === 'workers.state',
            ));

            self::assertSame([], $inventory['workers']);
            self::assertCount(1, $workerState);
            self::assertSame('unknown', $workerState[0]['value']);
            self::assertSame('blocked', $inventory['coverage'][2]['status']);
            self::assertNotNull($inventory['coverage'][2]['gap']);
            self::assertStringContainsString('worker absence is unverified', $inventory['coverage'][2]['gap']);
        } finally {
            unlink($root . '/proc/123/comm');
            rmdir($root . '/proc/123');
            rmdir($root . '/proc');
            unlink($root . '/commands.json');
            rmdir($root);
        }
    }

    /** @return RuntimeInventory */
    private function collect(string $name): array
    {
        $root = dirname(__DIR__) . '/fixtures/runtime/' . $name;

        return (new RuntimeInventoryCollector(
            new FixtureProcessRunner($root),
            $root,
            '2026-10-25T00:00:00Z',
        ))->collect();
    }

    private function copyDirectory(string $source, string $destination): void
    {
        mkdir($destination, 0777, true);
        foreach (new \DirectoryIterator($source) as $entry) {
            if ($entry->isDot()) {
                continue;
            }
            $path = $entry->getPathname();
            $target = $destination . '/' . $entry->getFilename();
            if ($entry->isLink()) {
                $linkTarget = readlink($path);
                self::assertIsString($linkTarget);
                symlink($linkTarget, $target);
            } elseif ($entry->isDir()) {
                $this->copyDirectory($path, $target);
            } else {
                copy($path, $target);
            }
        }
    }

    /** @param RuntimeInventory $inventory */
    private function factValue(array $inventory, string $key): mixed
    {
        foreach ($inventory['facts'] as $fact) {
            if ($fact['key'] === $key) {
                return $fact['value'];
            }
        }

        return null;
    }

    private function removeTemporaryTree(string $root): void
    {
        foreach (new \DirectoryIterator($root) as $entry) {
            if ($entry->isDot()) {
                continue;
            }
            if ($entry->isLink() || $entry->isFile()) {
                unlink($entry->getPathname());
            } elseif ($entry->isDir()) {
                $this->removeTemporaryTree($entry->getPathname());
            }
        }
        rmdir($root);
    }
}
