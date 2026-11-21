<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\RuntimeInventory;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use voku\PhpRuntimeAudit\Advisories\AdvisoryCatalog;
use voku\PhpRuntimeAudit\Advisories\AdvisoryEvaluator;
use voku\PhpRuntimeAudit\Advisories\RuntimeAuditReportBuilder;
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

    public function test_explicit_fpm_config_option_is_recorded_without_persisting_raw_arguments(): void
    {
        $commandLine = "/usr/sbin/php-fpm8.2\0--secret=DO_NOT_PERSIST\0--fpm-config=/srv/php82/custom.conf\0";
        file_put_contents($this->root . '/proc/123/cmdline', $commandLine);

        $worker = $this->collect()['workers'][0];

        self::assertSame('/srv/php82/custom.conf', $worker['fpm_configuration_path']);
        self::assertSame('observed', $worker['fpm_configuration_state']);
        self::assertSame(1, $worker['parent_pid']);
        self::assertStringNotContainsString('DO_NOT_PERSIST', json_encode($worker, JSON_THROW_ON_ERROR));
    }

    public function test_rewritten_fpm_master_title_supplies_its_config_path(): void
    {
        file_put_contents($this->root . '/proc/123/cmdline', "php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)\0\0\0");

        $worker = $this->collect()['workers'][0];

        self::assertSame('/etc/php/8.2/fpm/php-fpm.conf', $worker['fpm_configuration_path']);
        self::assertSame('observed', $worker['fpm_configuration_state']);
    }

    public function test_custom_fpm_config_does_not_consume_the_binary_default_config_tree(): void
    {
        file_put_contents($this->root . '/proc/123/cmdline', "/usr/sbin/php-fpm8.2\0-y\0/srv/php82/custom.conf\0");
        $inventory = $this->collect();
        $worker = $inventory['workers'][0];
        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());

        self::assertSame('/srv/php82/custom.conf', $worker['fpm_configuration_path']);
        foreach ($evaluation['assessments'] as $assessment) {
            if ($assessment['subject_id'] === $worker['id'] && str_contains($assessment['record_id'], 'CVE-2026-115560')) {
                self::assertSame('unknown', $assessment['verdict']);
                self::assertSame('unknown', $assessment['patch_status']);
                self::assertSame([], $assessment['patch_evidence_ids']);

                return;
            }
        }

        self::fail('Missing configuration advisory assessment for the custom-config worker.');
    }

    public function test_symlinked_fpm_entrypoint_keeps_default_tree_configuration_unknown(): void
    {
        $fpmDirectory = $this->root . '/etc/php/8.2/fpm';
        $entrypoint = $fpmDirectory . '/php-fpm.conf';
        $customDirectory = $this->root . '/usr/local/etc';
        mkdir($fpmDirectory . '/pool.d', 0777, true);
        mkdir($customDirectory, 0777, true);
        file_put_contents($customDirectory . '/php-fpm.conf', "; custom FPM configuration\n");
        self::assertTrue(symlink($customDirectory . '/php-fpm.conf', $entrypoint));
        file_put_contents(
            $fpmDirectory . '/pool.d/00-unrelated-default.conf',
            "[www]\nphp_admin_value[session.upload_progress.enabled]=1\nphp_admin_value[session.serialize_handler]=php_serialize\n",
        );

        $inventory = $this->collect();
        $worker = $inventory['workers'][0];
        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());
        $entrypointRootsFacts = array_values(array_filter(
            $inventory['facts'],
            static fn(array $fact): bool => $fact['key'] === 'configuration.fpm_entrypoint_symlink_roots',
        ));

        self::assertCount(1, $entrypointRootsFacts);
        self::assertSame(['/etc/php/8.2/fpm'], $entrypointRootsFacts[0]['value']);
        self::assertSame('blocked', $inventory['coverage'][3]['status']);
        foreach ($evaluation['assessments'] as $assessment) {
            if ($assessment['subject_id'] === $worker['id'] && str_contains($assessment['record_id'], 'CVE-2026-115560')) {
                self::assertSame('unknown', $assessment['verdict']);
                self::assertSame('unknown', $assessment['patch_status']);
                self::assertSame([], $assessment['patch_evidence_ids']);

                return;
            }
        }

        self::fail('Missing configuration advisory assessment for the symlinked-config worker.');
    }

    public function test_pool_worker_inherits_its_captured_masters_custom_config(): void
    {
        file_put_contents($this->root . '/proc/123/cmdline', "/usr/sbin/php-fpm8.2\0-y\0/srv/php82/custom.conf\0");
        mkdir($this->root . '/proc/124');
        $masterStat = file_get_contents($this->root . '/proc/123/stat');
        self::assertIsString($masterStat);
        $poolStat = str_replace(
            ['123 (php-fpm8.2) S 1 ', '12345'],
            ['124 (php-fpm8.2) S 123 ', '12450'],
            $masterStat,
        );
        file_put_contents($this->root . '/proc/124/comm', 'php-fpm8.2');
        file_put_contents($this->root . '/proc/124/stat', $poolStat);
        file_put_contents($this->root . '/proc/124/cmdline', "php-fpm: pool www\0\0");

        $inventory = $this->collect();
        $poolWorker = null;
        foreach ($inventory['workers'] as $worker) {
            if ($worker['pid'] === 124) {
                $poolWorker = $worker;
                break;
            }
        }
        self::assertIsArray($poolWorker);
        self::assertSame(123, $poolWorker['parent_pid']);
        self::assertSame('pool', $poolWorker['fpm_configuration_state']);
        self::assertSame('www', $poolWorker['fpm_pool_name']);

        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());
        foreach ($evaluation['assessments'] as $assessment) {
            if ($assessment['subject_id'] === $poolWorker['id'] && str_contains($assessment['record_id'], 'CVE-2026-115560')) {
                self::assertSame('unknown', $assessment['verdict']);
                self::assertSame('unknown', $assessment['patch_status']);
                self::assertSame([], $assessment['patch_evidence_ids']);

                return;
            }
        }

        self::fail('Missing configuration advisory assessment for the pool worker.');
    }

    /** @return iterable<string, array{bool}> */
    public static function poolStoreLayouts(): iterable
    {
        yield 'isolated per-pool session stores' => [true];
        yield 'shared default session store of one install' => [false];
    }

    #[DataProvider('poolStoreLayouts')]
    public function test_fpm_configuration_risk_is_scoped_to_the_named_pool_worker(bool $isolatedStores): void
    {
        $poolDirectory = $this->root . '/etc/php/8.2/fpm/pool.d';
        mkdir($poolDirectory, 0777, true);
        file_put_contents(
            $poolDirectory . '/workers.conf',
            "[www]\nphp_admin_flag[session.upload_progress.enabled]=on\n"
            . "php_admin_value[session.serialize_handler]=php_binary\n"
            . ($isolatedStores ? "php_admin_value[session.save_path]=/var/lib/php/sessions-www\n" : '')
            . "[safe]\nphp_admin_flag[session.upload_progress.enabled]=off\n"
            . "php_admin_value[session.serialize_handler]=php\n"
            . ($isolatedStores ? "php_admin_value[session.save_path]=/var/lib/php/sessions-safe\n" : ''),
        );

        $masterStat = file_get_contents($this->root . '/proc/123/stat');
        self::assertIsString($masterStat);
        foreach ([124 => ['www', 12450], 125 => ['safe', 12550]] as $pid => [$poolName, $startTicks]) {
            $directory = $this->root . '/proc/' . $pid;
            mkdir($directory);
            $stat = str_replace(
                ['123 (php-fpm8.2) S 1 ', '12345'],
                [$pid . ' (php-fpm8.2) S 123 ', (string) $startTicks],
                $masterStat,
            );
            file_put_contents($directory . '/comm', 'php-fpm8.2');
            file_put_contents($directory . '/stat', $stat);
            file_put_contents($directory . '/cmdline', "php-fpm: pool " . $poolName . "\0\0");
            mkdir($directory . '/ns', 0777, true);
            symlink('mnt:[4026531836]', $directory . '/ns/mnt');
            $rootIdentity = file_get_contents($this->root . '/proc/self/root');
            self::assertIsString($rootIdentity);
            file_put_contents($directory . '/root', $rootIdentity);
        }

        $inventory = $this->collect();
        $workersByPool = [];
        foreach ($inventory['workers'] as $worker) {
            if ($worker['pid'] === 124 || $worker['pid'] === 125) {
                $workersByPool[$worker['fpm_pool_name'] ?? 'missing'] = $worker;
            }
        }
        self::assertSame('worker-124-12450', $workersByPool['www']['id']);
        self::assertSame('worker-125-12550', $workersByPool['safe']['id']);
        self::assertNull($workersByPool['www']['executable_path']);
        self::assertNull($workersByPool['safe']['executable_path']);

        $assessmentsBySubject = [];
        foreach ((new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load())['assessments'] as $assessment) {
            if (str_contains($assessment['record_id'], 'CVE-2026-115560')) {
                $assessmentsBySubject[$assessment['subject_id']] = $assessment;
            }
        }
        $riskyAssessment = $assessmentsBySubject[$workersByPool['www']['id']] ?? null;
        $safeAssessment = $assessmentsBySubject[$workersByPool['safe']['id']] ?? null;

        self::assertIsArray($riskyAssessment);
        self::assertSame('needs_investigation', $riskyAssessment['verdict']);
        self::assertSame('unknown', $riskyAssessment['patch_status']);
        self::assertStringContainsString('contain upload progress enabled and a serialization handler named', $riskyAssessment['rationale']);
        self::assertIsArray($safeAssessment);
        // The www pool's same-context risk is never attributed to the safe pool. Only when both
        // pools use the install's default session store does the safe pool become a reader of the
        // php_binary records www writes, which the shared-store correlation reports.
        self::assertSame($isolatedStores ? 'unknown' : 'needs_investigation', $safeAssessment['verdict']);
        self::assertSame('unknown', $safeAssessment['patch_status']);
        self::assertStringNotContainsString('contain upload progress enabled and a serialization handler named', $safeAssessment['rationale']);
        if (!$isolatedStores) {
            self::assertStringContainsString('appear to share one default session location', $safeAssessment['rationale']);
        }
    }

    public function test_pool_title_without_captured_parent_does_not_use_the_default_config_tree(): void
    {
        file_put_contents($this->root . '/proc/123/cmdline', "php-fpm: pool www\0\0");
        $inventory = $this->collect();
        $worker = $inventory['workers'][0];
        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());

        self::assertSame('pool', $worker['fpm_configuration_state']);
        foreach ($evaluation['assessments'] as $assessment) {
            if ($assessment['subject_id'] === $worker['id'] && str_contains($assessment['record_id'], 'CVE-2026-115560')) {
                self::assertSame('unknown', $assessment['verdict']);
                self::assertSame('unknown', $assessment['patch_status']);
                self::assertSame([], $assessment['patch_evidence_ids']);

                return;
            }
        }

        self::fail('Missing configuration advisory assessment for the pool-title worker.');
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
        mkdir($this->root . '/proc/124/ns', 0777, true);
        symlink('mnt:[4026531836]', $this->root . '/proc/124/ns/mnt');
        $rootIdentity = file_get_contents($this->root . '/proc/self/root');
        self::assertIsString($rootIdentity);
        file_put_contents($this->root . '/proc/124/root', $rootIdentity);
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
        $commands['commands']['dpkg-packages']['stdout'] .= "php7.4-fpm\t7.4.33-1+deb.sury.org+1\tinstall ok installed\tamd64\n";
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
        // The 7.4 worker's own configuration is risky. The 8.2 worker's is not, and nothing is
        // merged into its context; both are Debian/sury packages sharing /var/lib/php/sessions by
        // default, so only the shared-store correlation raises it.
        self::assertSame('needs_investigation', $assessments[$workerVersions[123][0]]['verdict']);
        self::assertStringContainsString('appear to share one default session location', $assessments[$workerVersions[123][0]]['rationale']);
        self::assertStringNotContainsString('contain upload progress enabled and a serialization handler named', $assessments[$workerVersions[123][0]]['rationale']);
        self::assertSame('needs_investigation', $assessments[$workerVersions[124][0]]['verdict']);
        self::assertStringContainsString('contain upload progress enabled and a serialization handler named', $assessments[$workerVersions[124][0]]['rationale']);
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

    public function test_session_save_path_credentials_are_never_collected(): void
    {
        mkdir($this->root . '/etc/php/8.2/fpm/pool.d', 0777, true);
        file_put_contents(
            $this->root . '/etc/php/8.2/fpm/pool.d/stores.conf',
            "[a]\nphp_admin_value[session.save_handler]=redis\nphp_admin_value[session.save_path]=\"tcp://10.0.0.5:6379?auth=s3cr3t-a&database=2\"\n"
            . "[b]\nphp_value[session.save_handler]=redis\nphp_value[session.save_path]=\"tcp://10.0.0.5:6379?auth=s3cr3t-a&database=2\"\n"
            . "[c]\nphp_value[session.save_handler]=redis\nphp_value[session.save_path]=\"tcp://user:pa55@10.0.0.6:6379\"\n"
            . "[d]\nphp_value[session.save_path]=\"2;/var/lib/php/sessions-d\"\n",
        );
        $inventory = $this->collect();
        $encoded = json_encode($inventory, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        foreach (['s3cr3t', 'pa55', 'auth=', '10.0.0.5', '10.0.0.6', 'user:'] as $secret) {
            self::assertStringNotContainsString($secret, $encoded);
        }
        $byContext = [];
        foreach ($inventory['configuration_by_sapi']['fpm']['session.save_path']['observations'] as $observation) {
            $byContext[$observation['context']] = $observation['value'];
        }
        self::assertStringStartsWith('redacted:tcp:', $byContext['pool:a']);
        self::assertSame($byContext['pool:a'], $byContext['pool:b']);
        self::assertNotSame($byContext['pool:a'], $byContext['pool:c']);
        self::assertSame('2;/var/lib/php/sessions-d', $byContext['pool:d']);
        self::assertSame('observed', $inventory['configuration_by_sapi']['fpm']['session.save_handler']['state']);
        self::assertSame('redis', $inventory['configuration_by_sapi']['fpm']['session.save_handler']['value']);
    }

    /** @return iterable<string, array{string, string, string}> */
    public static function crossInstallStores(): iterable
    {
        yield 'explicitly shared store' => ['/var/lib/php/shared', '/var/lib/php/shared', 'needs_investigation'];
        yield 'shared store spelled with a trailing slash' => ['/var/lib/php/shared/', '/var/lib/php/shared', 'needs_investigation'];
        yield 'isolated stores' => ['/var/lib/php/app-a', '/var/lib/php/app-b', 'unknown'];
        yield 'both default locations of different installs' => ['', '', 'unknown'];
    }

    /** @return iterable<string, array{string, string}> */
    public static function sharedStoreSerializerPairs(): iterable
    {
        yield 'igbinary writer, php reader' => ['igbinary', 'php'];
        yield 'php writer, php_serialize reader' => ['php', 'php_serialize'];
    }

    #[DataProvider('sharedStoreSerializerPairs')]
    public function test_any_serializer_difference_on_a_shared_store_requests_investigation(string $writerSerializer, string $readerSerializer): void
    {
        mkdir($this->root . '/usr/local/etc/php-fpm.d', 0777, true);
        file_put_contents(
            $this->root . '/usr/local/etc/php-fpm.d/writer.conf',
            "[writer]\nphp_admin_flag[session.upload_progress.enabled]=on\nphp_admin_value[session.serialize_handler]=" . $writerSerializer
            . "\nphp_admin_value[session.save_path]=/var/lib/php/shared\n",
        );
        mkdir($this->root . '/etc/php/8.2/fpm/pool.d', 0777, true);
        file_put_contents(
            $this->root . '/etc/php/8.2/fpm/pool.d/www.conf',
            "[www]\nphp_admin_value[session.serialize_handler]=" . $readerSerializer . "\nphp_admin_value[session.save_path]=/var/lib/php/shared\n",
        );
        $inventory = $this->collect();
        self::assertContains('on', array_column($inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled']['observations'], 'value'));

        foreach ((new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load())['assessments'] as $assessment) {
            if (str_contains($assessment['record_id'], 'CVE-2026-115560')
                && str_starts_with($assessment['subject_id'], 'worker-')) {
                self::assertSame('needs_investigation', $assessment['verdict']);
                self::assertStringContainsString('configure the same session store', $assessment['rationale']);

                return;
            }
        }
        self::fail('Missing configuration advisory assessment.');
    }

    #[DataProvider('crossInstallStores')]
    public function test_cross_install_session_store_correlation(string $writerPath, string $readerPath, string $expected): void
    {
        // Writer: a separate PHP install's pool enables upload progress with php_serialize.
        mkdir($this->root . '/usr/local/etc/php-fpm.d', 0777, true);
        file_put_contents(
            $this->root . '/usr/local/etc/php-fpm.d/writer.conf',
            "[writer]\nphp_admin_value[session.upload_progress.enabled]=1\nphp_admin_value[session.serialize_handler]=php_serialize\n"
            . ($writerPath === '' ? '' : "php_admin_value[session.save_path]=" . $writerPath . "\n"),
        );
        // Reader: the audited 8.2 worker keeps the php serializer from its php.ini.
        mkdir($this->root . '/etc/php/8.2/fpm/pool.d', 0777, true);
        file_put_contents(
            $this->root . '/etc/php/8.2/fpm/pool.d/www.conf',
            "[www]\n" . ($readerPath === '' ? '' : "php_admin_value[session.save_path]=" . $readerPath . "\n") . "pm=dynamic\n",
        );
        $evaluation = (new AdvisoryEvaluator())->evaluate($this->collect(), AdvisoryCatalog::load());

        foreach ($evaluation['assessments'] as $assessment) {
            if (str_contains($assessment['record_id'], 'CVE-2026-115560')
                && str_starts_with($assessment['subject_id'], 'worker-')) {
                self::assertSame($expected, $assessment['verdict']);
                self::assertSame('unknown', $assessment['patch_status']);
                if ($expected === 'needs_investigation') {
                    self::assertStringContainsString('configure the same session store', $assessment['rationale']);
                    self::assertStringContainsString('register their own save handler', $assessment['rationale']);
                }
                $exposure = null;
                foreach ($evaluation['facts'] as $fact) {
                    if (str_starts_with($fact['key'], 'advisory.CVE-2026-115560.worker-') && str_ends_with($fact['key'], '.configuration_exposure')) {
                        $exposure = $fact['value'];
                    }
                }
                self::assertIsArray($exposure);
                // The audited worker's own php.ini disables upload progress; without a shared-store
                // match that is only "not observed", which never clears a verdict.
                self::assertSame($expected === 'needs_investigation' ? 'needs_investigation' : 'not_observed', $exposure['state']);

                return;
            }
        }
        self::fail('Missing configuration advisory assessment.');
    }

    public function test_pools_without_session_overrides_inherit_global_values_in_store_correlation(): void
    {
        file_put_contents($this->root . '/etc/php/8.2/fpm/php.ini', "session.upload_progress.enabled=1\nsession.serialize_handler=php\n");
        mkdir($this->root . '/etc/php/8.2/fpm/pool.d', 0777, true);
        file_put_contents($this->root . '/etc/php/8.2/fpm/pool.d/custom.conf', "[custom]\nphp_admin_value[session.serialize_handler]=igbinary\n");
        file_put_contents($this->root . '/etc/php/8.2/fpm/pool.d/www.conf', "[www]\npm=dynamic\n");

        foreach ((new AdvisoryEvaluator())->evaluate($this->collect(), AdvisoryCatalog::load())['assessments'] as $assessment) {
            if (str_contains($assessment['record_id'], 'CVE-2026-115560')
                && str_starts_with($assessment['subject_id'], 'worker-')) {
                self::assertSame('needs_investigation', $assessment['verdict']);
                self::assertStringContainsString('global (pools without overrides)', $assessment['rationale']);

                return;
            }
        }
        self::fail('Missing configuration advisory assessment.');
    }

    public function test_debian_apache_and_fpm_share_the_packaged_default_session_store(): void
    {
        mkdir($this->root . '/etc/php/8.2/apache2', 0777, true);
        file_put_contents($this->root . '/etc/php/8.2/apache2/php.ini', "session.upload_progress.enabled=1\nsession.serialize_handler=php_serialize\n");

        foreach ((new AdvisoryEvaluator())->evaluate($this->collect(), AdvisoryCatalog::load())['assessments'] as $assessment) {
            if (str_contains($assessment['record_id'], 'CVE-2026-115560')
                && str_starts_with($assessment['subject_id'], 'worker-')) {
                self::assertSame('needs_investigation', $assessment['verdict']);
                self::assertStringContainsString('apache2:/etc/php/8.2/apache2', $assessment['rationale']);

                return;
            }
        }
        self::fail('Missing configuration advisory assessment.');
    }

    /** @return iterable<string, array{string}> */
    public static function debianSessionPathSpellings(): iterable
    {
        yield 'explicit packaged path' => ['session.save_path=/var/lib/php/sessions'];
        yield 'explicit path with trailing slash and depth prefix' => ['session.save_path="2;/var/lib/php/sessions/"'];
    }

    #[DataProvider('debianSessionPathSpellings')]
    public function test_explicit_debian_session_path_groups_with_the_packaged_default(string $saveLine): void
    {
        mkdir($this->root . '/etc/php/8.2/apache2', 0777, true);
        file_put_contents($this->root . '/etc/php/8.2/apache2/php.ini', "session.upload_progress.enabled=1\nsession.serialize_handler=igbinary\n" . $saveLine . "\n");

        foreach ((new AdvisoryEvaluator())->evaluate($this->collect(), AdvisoryCatalog::load())['assessments'] as $assessment) {
            if (str_contains($assessment['record_id'], 'CVE-2026-115560')
                && str_starts_with($assessment['subject_id'], 'worker-')) {
                self::assertSame('needs_investigation', $assessment['verdict']);

                return;
            }
        }
        self::fail('Missing configuration advisory assessment.');
    }

    public function test_a_store_member_with_conflicting_values_keeps_the_target_exposure_unknown(): void
    {
        mkdir($this->root . '/etc/php/8.2/apache2/conf.d', 0777, true);
        file_put_contents($this->root . '/etc/php/8.2/apache2/php.ini', "session.upload_progress.enabled=1\nsession.serialize_handler=php\n");
        file_put_contents($this->root . '/etc/php/8.2/apache2/conf.d/99-x.ini', "session.serialize_handler=igbinary\n");
        $evaluation = (new AdvisoryEvaluator())->evaluate($this->collect(), AdvisoryCatalog::load());

        foreach ($evaluation['facts'] as $fact) {
            if (str_starts_with($fact['key'], 'advisory.CVE-2026-115560.worker-') && str_ends_with($fact['key'], '.configuration_exposure')
                && is_array($fact['value'])) {
                self::assertSame('unknown', $fact['value']['state']);

                return;
            }
        }
        self::fail('Missing CVE-2026-115560 exposure fact.');
    }

    public function test_non_ascii_pool_names_cannot_break_report_encoding(): void
    {
        mkdir($this->root . '/etc/php/8.2/fpm/pool.d', 0777, true);
        $pools = '';
        for ($index = 0; $index < 12; ++$index) {
            $pools .= '[' . str_repeat('é', 40) . $index . "]\nphp_admin_value[session.upload_progress.enabled]=" . ($index % 2) . "\nphp_admin_value[session.serialize_handler]=" . ($index % 2 === 0 ? 'php' : 'igbinary') . "\nphp_admin_value[session.save_path]=/var/lib/php/shared\n";
        }
        file_put_contents($this->root . '/etc/php/8.2/fpm/pool.d/many.conf', $pools);
        $inventory = $this->collect();
        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());

        $report = (new RuntimeAuditReportBuilder())->build($inventory, $evaluation);
        self::assertNotEmpty($report['records']);
        foreach ($evaluation['assessments'] as $assessment) {
            self::assertSame(1, preg_match('//u', $assessment['rationale']));
            self::assertLessThanOrEqual(1999, strlen($assessment['rationale']));
        }
    }

    public function test_cve_126714_global_files_backend_is_not_hidden_by_a_pool_override(): void
    {
        file_put_contents($this->root . '/etc/php/8.2/fpm/php.ini', "session.upload_progress.enabled=0\nsession.serialize_handler=php\nsession.save_handler=files\n");
        mkdir($this->root . '/etc/php/8.2/fpm/pool.d', 0777, true);
        file_put_contents($this->root . '/etc/php/8.2/fpm/pool.d/www.conf', "[www]\nphp_admin_value[session.save_handler]=redis\n");
        $evaluation = (new AdvisoryEvaluator())->evaluate($this->collect(), AdvisoryCatalog::load());

        foreach ($evaluation['facts'] as $fact) {
            if (str_starts_with($fact['key'], 'advisory.CVE-2026-126714.worker-') && str_ends_with($fact['key'], '.configuration_exposure')
                && is_array($fact['value'])) {
                self::assertSame('needs_investigation', $fact['value']['state']);

                return;
            }
        }
        self::fail('Missing CVE-2026-126714 exposure fact.');
    }

    public function test_quoted_values_with_inline_comments_are_unquoted(): void
    {
        file_put_contents($this->root . '/etc/php/8.2/fpm/php.ini', "session.serialize_handler = \"php_serialize\" ; site default\nsession.save_path = \"/var/lib/php/shared\" # shared\n");
        $inventory = $this->collect();

        self::assertSame('php_serialize', $inventory['configuration_by_sapi']['fpm']['session.serialize_handler']['value']);
        self::assertSame('/var/lib/php/shared', $inventory['configuration_by_sapi']['fpm']['session.save_path']['value']);
    }

    public function test_yes_counts_as_an_enabled_upload_progress_value(): void
    {
        file_put_contents($this->root . '/etc/php/8.2/fpm/php.ini', "session.upload_progress.enabled = Yes \nsession.serialize_handler=php_binary\n");
        foreach ((new AdvisoryEvaluator())->evaluate($this->collect(), AdvisoryCatalog::load())['assessments'] as $assessment) {
            if (str_contains($assessment['record_id'], 'CVE-2026-115560')
                && str_starts_with($assessment['subject_id'], 'worker-')) {
                self::assertSame('needs_investigation', $assessment['verdict']);

                return;
            }
        }
        self::fail('Missing configuration advisory assessment.');
    }

    /** @return iterable<string, array{string, string}> */
    public static function sessionBackends(): iterable
    {
        yield 'files backend configured' => ["session.save_handler = files\n", 'needs_investigation'];
        yield 'other backend configured' => ["session.save_handler = redis\n", 'unknown'];
        yield 'backend unset' => ['', 'unknown'];
    }

    #[DataProvider('sessionBackends')]
    public function test_cve_126714_exposure_follows_the_configured_backend_without_changing_the_verdict(string $line, string $expectedState): void
    {
        file_put_contents($this->root . '/etc/php/8.2/fpm/php.ini', "session.upload_progress.enabled=0\nsession.serialize_handler=php\n" . $line);
        $evaluation = (new AdvisoryEvaluator())->evaluate($this->collect(), AdvisoryCatalog::load());

        $state = null;
        foreach ($evaluation['facts'] as $fact) {
            if (str_starts_with($fact['key'], 'advisory.CVE-2026-126714.worker-') && str_ends_with($fact['key'], '.configuration_exposure')
                && is_array($fact['value'])) {
                $state = $fact['value']['state'];
                self::assertIsString($fact['value']['reason']);
                self::assertStringContainsString('register their own save handler', $fact['value']['reason']);
            }
        }
        self::assertSame($expectedState, $state);
        foreach ($evaluation['assessments'] as $assessment) {
            if (str_contains($assessment['record_id'], 'CVE-2026-126714')
                && str_starts_with($assessment['subject_id'], 'worker-')) {
                // No vendor rule is bundled: the verdict stays patch-driven and unknown.
                self::assertSame('unknown', $assessment['verdict']);
            }
        }
    }

    public function test_docker_main_fpm_configuration_is_scoped_to_fpm(): void
    {
        mkdir($this->root . '/usr/local/etc', 0777, true);
        file_put_contents($this->root . '/usr/local/etc/php-fpm.conf', "php_admin_value[session.serialize_handler]=php_binary\n");
        $inventory = $this->collect();

        self::assertContains('/usr/local/etc/php-fpm.conf', $inventory['configuration_by_sapi']['fpm']['session.serialize_handler']['files']);
        self::assertSame('unknown', $inventory['configuration_by_sapi']['cli']['session.serialize_handler']['state']);
    }

    /** @return iterable<string, array{string, string, string, string}> */
    public static function fpmBooleanDirectiveVariants(): iterable
    {
        yield 'php_flag on' => ['php_flag', 'on', 'on', 'needs_investigation'];
        yield 'php_admin_flag yes' => ['php_admin_flag', 'yes', 'yes', 'needs_investigation'];
        yield 'php_admin_flag off' => ['php_admin_flag', 'off', 'off', 'unknown'];
        yield 'quoted php_flag with inline comment' => ['php_flag', '"on" ; note', 'on', 'needs_investigation'];
        yield 'quoted php_admin_flag with hash comment' => ['php_admin_flag', "'yes' # note", 'yes', 'needs_investigation'];
        yield 'quoted php_admin_flag off with inline comment' => ['php_admin_flag', '"off" ; note', 'off', 'unknown'];
    }

    #[DataProvider('fpmBooleanDirectiveVariants')]
    public function test_fpm_boolean_pool_flags_are_preserved_and_assessed(
        string $directive,
        string $rawValue,
        string $expectedValue,
        string $expectedVerdict,
    ): void {
        mkdir($this->root . '/etc/php/8.2/fpm/pool.d', 0777, true);
        $file = '/etc/php/8.2/fpm/pool.d/flags.conf';
        file_put_contents(
            $this->root . $file,
            "[www]\n" . $directive . '[session.upload_progress.enabled]=' . $rawValue . "\n"
            . "php_admin_value[session.serialize_handler]=\"php_binary\" ; note\n",
        );
        $poolSubjectId = $this->addFpmPoolWorker(123, 124, 12450, 'www');
        $inventory = $this->collect();
        $uploadSetting = $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled'];

        self::assertContains(
            [
                'value' => $expectedValue,
                'file' => $file,
                'context' => 'pool:www',
                'configuration_root' => '/etc/php/8.2/fpm',
            ],
            $uploadSetting['observations'],
        );

        foreach ((new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load())['assessments'] as $assessment) {
            if (!str_contains($assessment['record_id'], 'CVE-2026-115560')
                || $assessment['subject_id'] !== $poolSubjectId) {
                continue;
            }

            self::assertSame($expectedVerdict, $assessment['verdict']);
            self::assertSame('unknown', $assessment['patch_status']);

            return;
        }

        self::fail('Missing configuration advisory assessment for the FPM worker.');
    }

    public function test_alpine_versioned_fpm_configuration_is_discovered_and_assessed(): void
    {
        $this->removeDirectory($this->root);
        $this->copyDirectory(dirname(__DIR__) . '/fixtures/runtime/alpine-fpm', $this->root);
        mkdir($this->root . '/etc/php82/php-fpm.d', 0777, true);
        $file = '/etc/php82/php-fpm.d/www.conf';
        file_put_contents(
            $this->root . $file,
            "[www]\nphp_admin_flag[session.upload_progress.enabled]=on\n"
            . "php_admin_value[session.serialize_handler]=php_binary\n",
        );
        $poolSubjectId = $this->addFpmPoolWorker(800, 801, 80100, 'www');

        $inventory = $this->collect();
        $uploadSetting = $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled'];

        self::assertContains(
            [
                'value' => 'on',
                'file' => $file,
                'context' => 'pool:www',
                'configuration_root' => '/etc/php82',
            ],
            $uploadSetting['observations'],
        );

        foreach ((new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load())['assessments'] as $assessment) {
            if (!str_contains($assessment['record_id'], 'CVE-2026-115560')
                || $assessment['subject_id'] !== $poolSubjectId) {
                continue;
            }

            self::assertSame('needs_investigation', $assessment['verdict']);
            self::assertSame('unknown', $assessment['patch_status']);

            return;
        }

        self::fail('Missing Alpine FPM configuration advisory assessment.');
    }

    public function test_alpine_php81_fpm_configuration_is_discovered_and_assessed(): void
    {
        $this->removeDirectory($this->root);
        $this->copyDirectory(dirname(__DIR__) . '/fixtures/runtime/alpine-fpm', $this->root);
        self::assertTrue(rename($this->root . '/usr/sbin/php-fpm82', $this->root . '/usr/sbin/php-fpm81'));
        chmod($this->root . '/usr/sbin/php-fpm81', 0755);

        foreach ([
            'proc/800/cmdline',
            'proc/800/comm',
            'proc/800/exe',
            'proc/800/stat',
        ] as $relativePath) {
            $path = $this->root . '/' . $relativePath;
            $contents = file_get_contents($path);
            self::assertIsString($contents);
            file_put_contents($path, str_replace(
                ['fpm-82', 'php-fpm82', '/usr/sbin/php-fpm82', '8.2.35', 'php82'],
                ['fpm-81', 'php-fpm81', '/usr/sbin/php-fpm81', '8.1.35', 'php81'],
                $contents,
            ));
        }

        $commandsPath = $this->root . '/commands.json';
        $commandsJson = file_get_contents($commandsPath);
        self::assertIsString($commandsJson);
        $commands = json_decode($commandsJson, true, 16, JSON_THROW_ON_ERROR);
        if (!is_array($commands)
            || !is_array($commands['commands'] ?? null)
            || !is_array($commands['commands']['apk-packages'] ?? null)) {
            self::fail('Invalid Alpine fixture command data.');
        }
        unset($commands['commands']['fpm-82']);
        $commands['commands'][DiscoveredPhpCommand::fromPath('/usr/sbin/php-fpm81', 'fpm')->id()] = [
            'exit_code' => 0,
            'stdout' => 'PHP 8.1.35 (fpm-fcgi) (built: fixture)',
        ];
        $commands['commands']['apk-packages']['stdout'] = "php81-8.1.35-r0\nphp81-fpm-8.1.35-r0\n";
        file_put_contents($commandsPath, json_encode($commands, JSON_THROW_ON_ERROR));

        mkdir($this->root . '/etc/php81/php-fpm.d', 0777, true);
        $file = '/etc/php81/php-fpm.d/www.conf';
        file_put_contents(
            $this->root . $file,
            "[www]\nphp_admin_flag[session.upload_progress.enabled]=on\n"
            . "php_admin_value[session.serialize_handler]=php_binary\n",
        );
        $poolSubjectId = $this->addFpmPoolWorker(800, 801, 80100, 'www');

        $inventory = $this->collect();
        $uploadSetting = $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled'];

        self::assertContains(
            [
                'value' => 'on',
                'file' => $file,
                'context' => 'pool:www',
                'configuration_root' => '/etc/php81',
            ],
            $uploadSetting['observations'],
        );

        foreach ((new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load())['assessments'] as $assessment) {
            if (!str_contains($assessment['record_id'], 'CVE-2026-115560')
                || $assessment['subject_id'] !== $poolSubjectId) {
                continue;
            }

            self::assertSame('needs_investigation', $assessment['verdict']);
            self::assertSame('unknown', $assessment['patch_status']);

            return;
        }

        self::fail('Missing Alpine PHP 8.1 FPM configuration advisory assessment.');
    }

    public function test_alpine_php810_fpm_configuration_is_discovered_and_assessed(): void
    {
        $this->removeDirectory($this->root);
        $this->copyDirectory(dirname(__DIR__) . '/fixtures/runtime/alpine-fpm', $this->root);
        self::assertTrue(rename($this->root . '/usr/sbin/php-fpm82', $this->root . '/usr/sbin/php-fpm810'));
        chmod($this->root . '/usr/sbin/php-fpm810', 0755);

        foreach ([
            'proc/800/cmdline',
            'proc/800/comm',
            'proc/800/exe',
            'proc/800/stat',
        ] as $relativePath) {
            $path = $this->root . '/' . $relativePath;
            $contents = file_get_contents($path);
            self::assertIsString($contents);
            file_put_contents($path, str_replace(
                ['fpm-82', 'php-fpm82', '/usr/sbin/php-fpm82', '8.2.35', 'php82'],
                ['fpm-810', 'php-fpm810', '/usr/sbin/php-fpm810', '8.10.1', 'php810'],
                $contents,
            ));
        }

        $commandsPath = $this->root . '/commands.json';
        $commandsJson = file_get_contents($commandsPath);
        self::assertIsString($commandsJson);
        $commands = json_decode($commandsJson, true, 16, JSON_THROW_ON_ERROR);
        if (!is_array($commands)
            || !is_array($commands['commands'] ?? null)
            || !is_array($commands['commands']['apk-packages'] ?? null)) {
            self::fail('Invalid Alpine fixture command data.');
        }
        unset($commands['commands']['fpm-82']);
        $commands['commands'][DiscoveredPhpCommand::fromPath('/usr/sbin/php-fpm810', 'fpm')->id()] = [
            'exit_code' => 0,
            'stdout' => 'PHP 8.10.1 (fpm-fcgi) (built: fixture)',
        ];
        $commands['commands']['apk-packages']['stdout'] = "php810-8.10.1-r0\nphp810-fpm-8.10.1-r0\n";
        file_put_contents($commandsPath, json_encode($commands, JSON_THROW_ON_ERROR));

        mkdir($this->root . '/etc/php810/php-fpm.d', 0777, true);
        $file = '/etc/php810/php-fpm.d/www.conf';
        file_put_contents(
            $this->root . $file,
            "[www]\nphp_admin_flag[session.upload_progress.enabled]=on\n"
            . "php_admin_value[session.serialize_handler]=php_binary\n",
        );
        $poolSubjectId = $this->addFpmPoolWorker(800, 801, 80100, 'www');

        $inventory = $this->collect();
        $uploadSetting = $inventory['configuration_by_sapi']['fpm']['session.upload_progress.enabled'];
        self::assertContains(
            [
                'value' => 'on',
                'file' => $file,
                'context' => 'pool:www',
                'configuration_root' => '/etc/php810',
            ],
            $uploadSetting['observations'],
        );

        foreach ((new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load())['assessments'] as $assessment) {
            if (!str_contains($assessment['record_id'], 'CVE-2026-115560')
                || $assessment['subject_id'] !== $poolSubjectId) {
                continue;
            }

            self::assertSame('needs_investigation', $assessment['verdict']);
            self::assertSame('unknown', $assessment['patch_status']);

            return;
        }

        self::fail('Missing Alpine PHP 8.10 FPM configuration advisory assessment.');
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
                // Not merged into one context, but both Debian installs share the packaged default
                // session store, where the serializers differ while 8.3 enables upload progress.
                self::assertSame('needs_investigation', $assessment['verdict']);
                self::assertSame('unknown', $assessment['patch_status']);
                self::assertStringContainsString('appear to share one default session location', $assessment['rationale']);
                self::assertStringNotContainsString('contain upload progress enabled and a serialization handler named', $assessment['rationale']);
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

    private function addFpmPoolWorker(int $masterPid, int $workerPid, int $startTicks, string $poolName): string
    {
        $masterDirectory = $this->root . '/proc/' . $masterPid;
        $masterStat = file_get_contents($masterDirectory . '/stat');
        $masterComm = file_get_contents($masterDirectory . '/comm');
        $masterExe = file_get_contents($masterDirectory . '/exe');
        if (!is_string($masterStat) || !is_string($masterComm) || !is_string($masterExe)) {
            throw new \LogicException('The FPM master fixture must have complete process identity.');
        }

        $workerStat = preg_replace(
            '/\A' . preg_quote((string) $masterPid, '/') . ' /',
            $workerPid . ' ',
            rtrim($masterStat, "\n"),
            1,
        );
        if (!is_string($workerStat)) {
            throw new \LogicException('Unable to construct the FPM pool worker process identity.');
        }
        $workerStat = preg_replace('/\) ([A-Z]) [0-9]+ /', ') $1 ' . $masterPid . ' ', $workerStat, 1);
        if (!is_string($workerStat)) {
            throw new \LogicException('Unable to bind the FPM pool worker to its master process.');
        }
        $workerStat = preg_replace('/[0-9]+\z/', (string) $startTicks, $workerStat, 1);
        if (!is_string($workerStat)) {
            throw new \LogicException('Unable to set the FPM pool worker start time.');
        }

        $workerDirectory = $this->root . '/proc/' . $workerPid;
        mkdir($workerDirectory, 0777, true);
        file_put_contents($workerDirectory . '/comm', $masterComm);
        file_put_contents($workerDirectory . '/exe', $masterExe);
        file_put_contents($workerDirectory . '/stat', $workerStat);
        file_put_contents($workerDirectory . '/cmdline', 'php-fpm: pool ' . $poolName . "\0\0");
        mkdir($workerDirectory . '/ns', 0777, true);
        symlink('mnt:[4026531836]', $workerDirectory . '/ns/mnt');
        $rootIdentity = file_get_contents($this->root . '/proc/self/root');
        if (!is_string($rootIdentity)) {
            throw new \LogicException('The FPM fixture must include a collector root identity.');
        }
        file_put_contents($workerDirectory . '/root', $rootIdentity);

        return 'worker-' . $workerPid . '-' . $startTicks;
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
            if ($entry->isLink() || !$entry->isDir()) {
                unlink($entry->getPathname());
            } else {
                $this->removeDirectory($entry->getPathname());
            }
        }
        rmdir($directory);
    }
}
