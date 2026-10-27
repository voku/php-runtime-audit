<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\RuntimeInventory;

use PHPUnit\Framework\TestCase;
use voku\PhpRuntimeAudit\RuntimeInventory\FixtureProcessRunner;
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
}
