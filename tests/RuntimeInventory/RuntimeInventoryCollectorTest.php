<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\RuntimeInventory;

use PHPUnit\Framework\TestCase;
use voku\PhpRuntimeAudit\RuntimeInventory\FixtureProcessRunner;
use voku\PhpRuntimeAudit\RuntimeInventory\DiscoveredPhpCommand;
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
                'dpkg-packages' => ['exit_code' => 0, 'stdout' => "php5.6-cli\t5.6.40-0+deb.sury.org+1\nphp7.4-cli\t7.4.33-1+deb.sury.org+1\n"],
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
            $lines[] = 'php' . $index . '-cli' . "\t" . '7.4.33-' . $index;
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

            self::assertSame('8.2.35', $inventory['runtimes'][0]['version']);
            self::assertNull($inventory['runtimes'][0]['extensions']);
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
