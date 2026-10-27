<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\RuntimeInventory;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use voku\PhpRuntimeAudit\Advisories\AdvisoryCatalog;
use voku\PhpRuntimeAudit\Advisories\AdvisoryEvaluator;
use voku\PhpRuntimeAudit\RuntimeInventory\FixtureProcessRunner;
use voku\PhpRuntimeAudit\RuntimeInventory\DiscoveredPhpCommand;
use voku\PhpRuntimeAudit\RuntimeInventory\RuntimeInventoryCollector;

/**
 * @phpstan-import-type RuntimeInventory from RuntimeInventoryCollector
 * @phpstan-import-type RuntimeConfigSetting from RuntimeInventoryCollector
 */
final class RuntimeWorkerEvidenceTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/pra-worker-' . bin2hex(random_bytes(8));
        $this->copyDirectory(dirname(__DIR__) . '/fixtures/runtime/debian-fpm', $this->root);
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->root);
    }

    /** @return iterable<string, array{string}> */
    public static function conflictingCommandLines(): iterable
    {
        yield 'different version' => ["/usr/sbin/php-fpm8.3\0--nodaemonize\0"];
        yield 'different explicit executable' => ["/usr/local/sbin/php-fpm8.2\0"];
        yield 'versioned basename' => ["php-fpm83\0"];
    }

    #[DataProvider('conflictingCommandLines')]
    public function test_conflicting_command_identity_cannot_verify_a_fixed_worker(string $commandLine): void
    {
        file_put_contents($this->root . '/proc/123/cmdline', $commandLine);
        $inventory = $this->collect();

        self::assertNull($inventory['workers'][0]['version']);
        self::assertNull($inventory['workers'][0]['executable_path']);
        self::assertNull($inventory['workers'][0]['process_start_ticks_since_boot']);
        foreach ((new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load())['assessments'] as $assessment) {
            if (str_starts_with($assessment['subject_id'], 'worker-') || str_starts_with($assessment['subject_id'], 'apache-')) {
                self::assertNotSame('verified_fixed', $assessment['patch_status']);
            }
        }
    }

    /** @return iterable<string, array{string}> */
    public static function usableCommandLines(): iterable
    {
        yield 'ordinary argv with secret' => ["/usr/sbin/php-fpm8.2\0--secret=DO_NOT_PERSIST\0"];
        yield 'master title' => ["php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)\0\0\0"];
        yield 'pool title' => ["php-fpm: pool www\0\0"];
    }

    #[DataProvider('usableCommandLines')]
    public function test_valid_argv_and_rewritten_titles_preserve_independent_worker_identity(string $commandLine): void
    {
        file_put_contents($this->root . '/proc/123/cmdline', $commandLine);
        $inventory = $this->collect();

        self::assertSame('8.2.35', $inventory['workers'][0]['version']);
        self::assertSame(12345, $inventory['workers'][0]['process_start_ticks_since_boot']);
        self::assertStringNotContainsString('DO_NOT_PERSIST', json_encode($inventory, JSON_THROW_ON_ERROR));
        $sources = array_values(array_filter($inventory['sources'], static fn(array $source): bool => $source['locator'] === '/proc/123/cmdline'));
        self::assertCount(1, $sources);
        self::assertSame('sha256:' . hash('sha256', $commandLine), $sources[0]['captured_digest']);
    }

    public function test_php85_fpm_worker_is_discovered_without_inventing_vendor_patch_status(): void
    {
        $fixtureRoot = dirname(__DIR__) . '/fixtures/runtime/debian-php85-fpm';
        $inventory = (new RuntimeInventoryCollector(
            new FixtureProcessRunner($fixtureRoot),
            $fixtureRoot,
            '2026-10-25T00:00:00Z',
        ))->collect();

        self::assertSame('8.5.0', $inventory['workers'][0]['version']);
        self::assertSame('/usr/sbin/php-fpm8.5', $inventory['workers'][0]['executable_path']);
        self::assertSame('php8.5-fpm', $inventory['packages'][1]['name']);
        foreach ((new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load())['assessments'] as $assessment) {
            self::assertSame('unknown', $assessment['patch_status']);
            self::assertSame('unknown', $assessment['compromise_evidence']['status']);
        }
    }

    public function test_side_by_side_fpm_workers_keep_version_specific_config_and_advisory_subjects(): void
    {
        if (!is_dir($this->root . '/usr/sbin')) {
            mkdir($this->root . '/usr/sbin', 0777, true);
        }
        file_put_contents($this->root . '/usr/sbin/php-fpm7.4', 'fixture PHP 7.4 FPM');
        mkdir($this->root . '/proc/124', 0777, true);
        file_put_contents($this->root . '/proc/124/comm', 'php-fpm7.4');
        file_put_contents($this->root . '/proc/124/stat', '124 (php-fpm7.4) S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12450');
        file_put_contents($this->root . '/proc/124/cmdline', "/usr/sbin/php-fpm7.4\0--nodaemonize\0");
        file_put_contents($this->root . '/proc/124/exe', '/usr/sbin/php-fpm7.4');
        mkdir($this->root . '/etc/php/7.4/fpm', 0777, true);
        file_put_contents($this->root . '/etc/php/7.4/fpm/php.ini', "session.upload_progress.enabled=1\nsession.serialize_handler=php_serialize\n");

        $commands = json_decode((string) file_get_contents($this->root . '/commands.json'), true, 16, JSON_THROW_ON_ERROR);
        if (!is_array($commands)
            || !is_array($commands['commands'] ?? null)
            || !is_array($commands['commands']['dpkg-packages'] ?? null)
            || !is_string($commands['commands']['dpkg-packages']['stdout'] ?? null)) {
            self::fail('Fixture command data is malformed.');
        }
        $id = DiscoveredPhpCommand::fromPath('/usr/sbin/php-fpm7.4', 'fpm')->id();
        $commands['commands'][$id] = ['exit_code' => 0, 'stdout' => 'PHP 7.4.33 (fpm-fcgi) (built: fixture)'];
        $commands['commands']['dpkg-packages']['stdout'] .= "php7.4-fpm\t7.4.33-1+deb.sury.org+1\n";
        file_put_contents($this->root . '/commands.json', json_encode($commands, JSON_THROW_ON_ERROR));

        $inventory = $this->collect();
        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());
        $workerVersions = [];
        foreach ($inventory['workers'] as $worker) {
            $workerVersions[$worker['pid']] = [$worker['id'], $worker['version']];
        }
        $assessments = [];
        foreach ($evaluation['assessments'] as $assessment) {
            if (str_contains($assessment['record_id'], 'CVE-2026-115560')) {
                $assessments[$assessment['subject_id']] = $assessment;
            }
        }

        self::assertSame('8.2.35', $workerVersions[123][1]);
        self::assertSame('7.4.33', $workerVersions[124][1]);
        self::assertNotSame($workerVersions[123][0], $workerVersions[124][0]);
        self::assertSame('unknown', $assessments[$workerVersions[123][0]]['verdict']);
        self::assertSame('needs_investigation', $assessments[$workerVersions[124][0]]['verdict']);
        self::assertSame('unknown', $assessments[$workerVersions[123][0]]['patch_status']);
        self::assertSame('unknown', $assessments[$workerVersions[124][0]]['patch_status']);
    }

    /** @return iterable<string, array{string|null}> */
    public static function unknownCommandLines(): iterable
    {
        yield 'missing' => [null];
        yield 'empty' => [''];
        yield 'unterminated' => ['/usr/sbin/php-fpm8.2'];
        yield 'unrecognized' => ["unrelated\0"];
        yield 'malformed argv0' => ["/usr/sbin/php-fpm8.2\n\0"];
        yield 'oversized' => ["/usr/sbin/php-fpm8.2\0" . str_repeat('x', 4097) . "\0"];
    }

    #[DataProvider('unknownCommandLines')]
    public function test_unknown_command_identity_does_not_supply_positive_version_proof(?string $commandLine): void
    {
        if ($commandLine !== null) {
            file_put_contents($this->root . '/proc/123/cmdline', $commandLine);
        } elseif (is_file($this->root . '/proc/123/cmdline')) {
            unlink($this->root . '/proc/123/cmdline');
        }

        self::assertNull($this->collect()['workers'][0]['version']);
    }

    #[DataProvider('usableCommandLines')]
    public function test_command_identity_does_not_override_the_stat_pid_guard(string $commandLine): void
    {
        file_put_contents($this->root . '/proc/123/cmdline', $commandLine);
        $stat = file_get_contents($this->root . '/proc/123/stat');
        self::assertIsString($stat);
        file_put_contents($this->root . '/proc/123/stat', preg_replace('/\A123 /', '124 ', $stat));

        $worker = $this->collect()['workers'][0];
        self::assertNull($worker['version']);
        self::assertNull($worker['process_start_ticks_since_boot']);
    }

    public function test_docker_pool_overrides_are_observed_and_request_investigation(): void
    {
        mkdir($this->root . '/usr/local/etc/php-fpm.d', 0777, true);
        file_put_contents($this->root . '/usr/local/etc/php-fpm.d/www.conf', "[www]\nphp_admin_value[session.upload_progress.enabled]=1\nphp_admin_value[session.serialize_handler]=php_binary\n");
        $inventory = $this->collect();
        $handler = $inventory['configuration_by_sapi']['fpm']['session.serialize_handler'];

        self::assertContains(
            [
                'value' => 'php_binary',
                'file' => '/usr/local/etc/php-fpm.d/www.conf',
                'context' => 'pool:www',
                'configuration_root' => '/usr/local/etc',
            ],
            $handler['observations'],
        );
        self::assertSame('unknown', $inventory['configuration_by_sapi']['cli']['session.serialize_handler']['state']);
        foreach ((new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load())['assessments'] as $assessment) {
            if (str_contains($assessment['record_id'], 'CVE-2026-115560')
                && str_starts_with($assessment['subject_id'], 'worker-')) {
                self::assertSame('unknown', $assessment['verdict']);
                self::assertSame('unknown', $assessment['patch_status']);
                return;
            }
        }
        self::fail('Missing configuration advisory assessment.');
    }

    public function test_docker_main_fpm_configuration_is_scoped_to_fpm(): void
    {
        mkdir($this->root . '/usr/local/etc', 0777, true);
        file_put_contents($this->root . '/usr/local/etc/php-fpm.conf', "php_admin_value[session.serialize_handler]=php_binary\n");
        $inventory = $this->collect();

        self::assertContains('/usr/local/etc/php-fpm.conf', $inventory['configuration_by_sapi']['fpm']['session.serialize_handler']['files']);
        self::assertSame('unknown', $inventory['configuration_by_sapi']['cli']['session.serialize_handler']['state']);
    }

    /** @return iterable<string, array{bool, bool}> */
    public static function multiplePoolOrders(): iterable
    {
        yield 'risky then safe pool file' => [false, false];
        yield 'safe then risky pool file' => [true, false];
        yield 'risky then safe main file' => [false, true];
        yield 'safe then risky main file' => [true, true];
    }

    #[DataProvider('multiplePoolOrders')]
    public function test_a_later_pool_cannot_hide_an_earlier_risky_pool(bool $reverse, bool $mainFile): void
    {
        $risky = "[risky]\nphp_admin_value[session.upload_progress.enabled]=1\nphp_admin_value[session.serialize_handler]=php_serialize\n";
        $safe = "[safe]\nphp_admin_value[session.upload_progress.enabled]=0\nphp_admin_value[session.serialize_handler]=php\n";
        mkdir($this->root . '/usr/local/etc/php-fpm.d', 0777, true);
        $file = $mainFile ? '/usr/local/etc/php-fpm.conf' : '/usr/local/etc/php-fpm.d/multiple.conf';
        file_put_contents($this->root . $file, $reverse ? $safe . $risky : $risky . $safe);
        $inventory = $this->collect();

        foreach (['session.upload_progress.enabled' => '1', 'session.serialize_handler' => 'php_serialize'] as $key => $value) {
            /** @var RuntimeConfigSetting $setting */
            $setting = $inventory['configuration_by_sapi']['fpm'][$key];
            /** @var RuntimeConfigSetting $cliSetting */
            $cliSetting = $inventory['configuration_by_sapi']['cli'][$key];
            /** @var RuntimeConfigSetting $apacheSetting */
            $apacheSetting = $inventory['configuration_by_sapi']['apache2'][$key];
            self::assertSame('conflict', $setting['state']);
            self::assertContains(
                [
                    'value' => $value,
                    'file' => $file,
                    'context' => 'pool:risky',
                    'configuration_root' => '/usr/local/etc',
                ],
                $setting['observations'],
            );
            self::assertSame('unknown', $cliSetting['state']);
            self::assertSame('unknown', $apacheSetting['state']);
        }
        foreach ((new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load())['assessments'] as $assessment) {
            if (str_contains($assessment['record_id'], 'CVE-2026-115560')
                && str_starts_with($assessment['subject_id'], 'worker-')) {
                self::assertSame('unknown', $assessment['verdict']);
                self::assertSame('unknown', $assessment['patch_status']);
                return;
            }
        }
        self::fail('Missing configuration advisory assessment.');
    }

    public function test_configuration_from_distinct_fpm_pools_is_not_combined_into_one_applicability_path(): void
    {
        mkdir($this->root . '/usr/local/etc/php-fpm.d', 0777, true);
        file_put_contents(
            $this->root . '/usr/local/etc/php-fpm.d/pools.conf',
            "[upload-only]\nphp_admin_value[session.upload_progress.enabled]=1\n"
            . "php_admin_value[session.serialize_handler]=php\n"
            . "[serializer-only]\nphp_admin_value[session.upload_progress.enabled]=0\n"
            . "php_admin_value[session.serialize_handler]=php_binary\n",
        );
        $inventory = $this->collect();
        $upload = $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled'];
        $serializer = $inventory['configuration_by_sapi']['fpm']['session.serialize_handler'];

        self::assertContains(
            [
                'value' => '1',
                'file' => '/usr/local/etc/php-fpm.d/pools.conf',
                'context' => 'pool:upload-only',
                'configuration_root' => '/usr/local/etc',
            ],
            $upload['observations'],
        );
        self::assertContains(
            [
                'value' => 'php_binary',
                'file' => '/usr/local/etc/php-fpm.d/pools.conf',
                'context' => 'pool:serializer-only',
                'configuration_root' => '/usr/local/etc',
            ],
            $serializer['observations'],
        );
        foreach ((new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load())['assessments'] as $assessment) {
            if (str_contains($assessment['record_id'], 'CVE-2026-115560')) {
                self::assertSame('unknown', $assessment['verdict']);
                self::assertSame('unknown', $assessment['patch_status']);
                return;
            }
        }
        self::fail('Missing configuration advisory assessment.');
    }

    public function test_global_fpm_settings_from_another_php_install_are_not_combined_with_a_pool_override(): void
    {
        mkdir($this->root . '/etc/php/8.3/fpm', 0777, true);
        file_put_contents(
            $this->root . '/etc/php/8.3/fpm/php.ini',
            "session.upload_progress.enabled=1\nsession.serialize_handler=php\n",
        );
        mkdir($this->root . '/etc/php/8.2/fpm/pool.d', 0777, true);
        file_put_contents(
            $this->root . '/etc/php/8.2/fpm/pool.d/www.conf',
            "[www]\nphp_admin_value[session.upload_progress.enabled]=0\n"
            . "php_admin_value[session.serialize_handler]=php_binary\n",
        );
        $inventory = $this->collect();
        $upload = $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled'];
        $serializer = $inventory['configuration_by_sapi']['fpm']['session.serialize_handler'];

        self::assertContains(
            [
                'value' => '1',
                'file' => '/etc/php/8.3/fpm/php.ini',
                'context' => 'global',
                'configuration_root' => '/etc/php/8.3/fpm',
            ],
            $upload['observations'],
        );
        self::assertContains(
            [
                'value' => 'php_binary',
                'file' => '/etc/php/8.2/fpm/pool.d/www.conf',
                'context' => 'pool:www',
                'configuration_root' => '/etc/php/8.2/fpm',
            ],
            $serializer['observations'],
        );
        foreach ((new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load())['assessments'] as $assessment) {
            if (str_contains($assessment['record_id'], 'CVE-2026-115560')) {
                self::assertSame('unknown', $assessment['verdict']);
                self::assertSame('unknown', $assessment['patch_status']);
                return;
            }
        }
        self::fail('Missing configuration advisory assessment.');
    }

    public function test_repeated_assignments_within_the_same_pool_keep_the_last_value(): void
    {
        mkdir($this->root . '/usr/local/etc/php-fpm.d', 0777, true);
        file_put_contents($this->root . '/usr/local/etc/php-fpm.d/www.conf', "[www]\nphp_admin_value[session.upload_progress.enabled]=1\nphp_admin_value[session.serialize_handler]=php_serialize\n[other]\n[www]\nphp_admin_value[session.upload_progress.enabled]=0\nphp_admin_value[session.serialize_handler]=php\n");
        $inventory = $this->collect();

        self::assertSame('observed', $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled']['state']);
        self::assertSame('0', $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled']['value']);
        self::assertSame('php', $inventory['configuration_by_sapi']['fpm']['session.serialize_handler']['value']);
    }

    public function test_admin_and_plain_pool_directives_preserve_unevaluated_precedence(): void
    {
        mkdir($this->root . '/usr/local/etc/php-fpm.d', 0777, true);
        file_put_contents($this->root . '/usr/local/etc/php-fpm.d/www.conf', "[www]\nphp_admin_value[session.upload_progress.enabled]=1\nphp_value[session.upload_progress.enabled]=0\n");
        $setting = $this->collect()['configuration_by_sapi']['fpm']['session.upload_progress.enabled'];

        self::assertSame('conflict', $setting['state']);
        self::assertContains(
            [
                'value' => '1',
                'file' => '/usr/local/etc/php-fpm.d/www.conf',
                'context' => 'pool:www',
                'configuration_root' => '/usr/local/etc',
            ],
            $setting['observations'],
        );
    }

    public function test_malformed_pool_header_cannot_overwrite_a_known_pool(): void
    {
        mkdir($this->root . '/usr/local/etc/php-fpm.d', 0777, true);
        file_put_contents($this->root . '/usr/local/etc/php-fpm.d/www.conf', "[risky]\nphp_admin_value[session.upload_progress.enabled]=1\n[malformed\nphp_admin_value[session.upload_progress.enabled]=0\n");
        $inventory = $this->collect();

        self::assertSame('conflict', $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled']['state']);
        self::assertSame('blocked', $inventory['coverage'][3]['status']);
        self::assertNotNull($inventory['coverage'][3]['gap']);
    }

    public function test_php_ini_sections_retain_global_last_value_semantics(): void
    {
        file_put_contents($this->root . '/etc/php/8.2/fpm/php.ini', "[risky]\nsession.upload_progress.enabled=1\nsession.serialize_handler=php_serialize\n[safe]\nsession.upload_progress.enabled=0\nsession.serialize_handler=php\n");
        $inventory = $this->collect();

        self::assertSame('observed', $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled']['state']);
        self::assertSame('0', $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled']['value']);
        self::assertSame('php', $inventory['configuration_by_sapi']['fpm']['session.serialize_handler']['value']);
    }

    public function test_pool_section_limit_reports_incomplete_configuration(): void
    {
        mkdir($this->root . '/usr/local/etc/php-fpm.d', 0777, true);
        $contents = '';
        for ($pool = 0; $pool < 100; ++$pool) {
            $contents .= '[pool' . $pool . "]\nphp_admin_value[session.upload_progress.enabled]=0\n";
        }
        file_put_contents($this->root . '/usr/local/etc/php-fpm.d/many.conf', $contents);
        $inventory = $this->collect();

        self::assertSame('unknown', $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled']['state']);
        self::assertSame('blocked', $inventory['coverage'][3]['status']);
        self::assertNotNull($inventory['coverage'][3]['gap']);
    }

    /** @return iterable<string, array{string|null, int|null, bool, bool, string}> */
    public static function failedCommandResults(): iterable
    {
        yield 'isolation unavailable' => ['network isolation is unavailable; command was not executed', null, false, false, 'network_isolation_unavailable'];
        yield 'isolation or query failure' => ['network isolation or isolated command failed; facts are unavailable', 1, false, false, 'network_isolation_or_query_failed'];
        yield 'arbitrary secret error' => ['SECRET_ERROR_DO_NOT_PERSIST', null, false, false, 'execution_unavailable'];
        yield 'nonzero query exit' => [null, 1, false, false, 'query_failed'];
        yield 'timeout' => [null, 0, true, false, 'timed_out'];
        yield 'truncated' => [null, 0, false, true, 'output_truncated'];
    }

    #[DataProvider('failedCommandResults')]
    public function test_failed_command_reports_bounded_diagnostics_without_secret_text(
        ?string $error,
        ?int $exitCode,
        bool $timedOut,
        bool $truncated,
        string $category,
    ): void {
        file_put_contents($this->root . '/commands.json', json_encode(['commands' => [
            'php-usr-bin' => [
                'exit_code' => $exitCode,
                'stdout' => '{"version":"8.2.35","sapi":"cli"}',
                'stderr' => 'SECRET_STDERR_DO_NOT_PERSIST',
                'error' => $error,
                'timed_out' => $timedOut,
                'truncated' => $truncated,
            ],
        ]], JSON_THROW_ON_ERROR));
        $inventory = $this->collect();

        self::assertSame([], $inventory['runtimes']);
        self::assertNull($inventory['workers'][0]['version']);
        $facts = array_values(array_filter($inventory['facts'], static fn(array $fact): bool => $fact['key'] === 'command.php-usr-bin.result'));
        self::assertCount(1, $facts);
        self::assertSame([
            'succeeded' => false,
            'exit_code' => $exitCode,
            'timed_out' => $timedOut,
            'truncated' => $truncated,
            'error_category' => $category,
        ], $facts[0]['value']);
        $json = json_encode($inventory, JSON_THROW_ON_ERROR);
        self::assertStringNotContainsString('SECRET_ERROR_DO_NOT_PERSIST', $json);
        self::assertStringNotContainsString('SECRET_STDERR_DO_NOT_PERSIST', $json);
    }

    /** @return RuntimeInventory */
    private function collect(): array
    {
        return (new RuntimeInventoryCollector(new FixtureProcessRunner($this->root), $this->root, '2026-10-25T00:00:00Z'))->collect();
    }

    private function copyDirectory(string $source, string $destination): void
    {
        mkdir($destination, 0777, true);
        foreach (new \DirectoryIterator($source) as $entry) {
            if ($entry->isDot()) {
                continue;
            }
            $target = $destination . '/' . $entry->getFilename();
            if ($entry->isDir()) {
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
            if ($entry->isDir()) {
                $this->removeDirectory($entry->getPathname());
            } else {
                unlink($entry->getPathname());
            }
        }
        rmdir($directory);
    }
}
