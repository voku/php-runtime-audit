<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\RuntimeInventory;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use voku\PhpRuntimeAudit\Advisories\AdvisoryCatalog;
use voku\PhpRuntimeAudit\Advisories\AdvisoryEvaluator;
use voku\PhpRuntimeAudit\RuntimeInventory\FixtureProcessRunner;
use voku\PhpRuntimeAudit\RuntimeInventory\RuntimeInventoryCollector;

/** @phpstan-import-type RuntimeInventory from RuntimeInventoryCollector */
final class RuntimePackageProvenanceTest extends TestCase
{
    private string $root;
    private string $apacheRoot;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/pra-integrity-' . bin2hex(random_bytes(8));
        $this->copyDirectory(dirname(__DIR__) . '/fixtures/runtime/synthetic-debian-integrity', $this->root);
        unlink($this->root . '/proc/123/exe');
        self::assertTrue(symlink('../../usr/sbin/php-fpm8.2', $this->root . '/proc/123/exe'));

        $this->apacheRoot = sys_get_temp_dir() . '/pra-apache-integrity-' . bin2hex(random_bytes(8));
        $this->copyDirectory(dirname(__DIR__) . '/fixtures/runtime/synthetic-debian-apache-integrity', $this->apacheRoot);
        $this->materializeApacheProcLinks();
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->root);
        $this->removeDirectory($this->apacheRoot);
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

    public function test_held_dpkg_packages_remain_installed_subjects_with_verified_worker_provenance(): void
    {
        $this->setDpkgPackageStatus($this->root, 'php8.2-fpm', 'hold ok installed');
        file_put_contents(
            $this->root . '/var/lib/dpkg/status',
            "Package: php8.2-fpm\nStatus: hold ok installed\nArchitecture: amd64\nVersion: 8.2.35-1~deb12u1\n\n",
        );
        $fpmInventory = $this->collect();
        self::assertContains(
            ['name' => 'php8.2-fpm', 'version' => '8.2.35-1~deb12u1', 'architecture' => 'amd64'],
            $fpmInventory['packages'],
        );
        self::assertTrue($fpmInventory['workers'][0]['package_provenance']['verified']);
        $fpmEvaluation = (new AdvisoryEvaluator())->evaluate($fpmInventory, AdvisoryCatalog::load());
        $fpmPackageId = 'package-' . substr(hash('sha256', "php8.2-fpm\0" . '8.2.35-1~deb12u1' . "\0" . 'amd64'), 0, 20);
        self::assertContains($fpmPackageId, array_column($fpmEvaluation['assessments'], 'subject_id'));

        $this->setDpkgPackageStatus($this->apacheRoot, 'libapache2-mod-php8.2', 'hold ok installed');
        file_put_contents(
            $this->apacheRoot . '/var/lib/dpkg/status',
            "Package: libapache2-mod-php8.2\nStatus: hold ok installed\nArchitecture: amd64\nVersion: 8.2.35-1~deb12u1\n",
        );
        $apacheInventory = $this->collectApache();
        self::assertContains(
            ['name' => 'libapache2-mod-php8.2', 'version' => '8.2.35-1~deb12u1', 'architecture' => 'amd64'],
            $apacheInventory['packages'],
        );
        self::assertTrue($apacheInventory['workers'][0]['package_provenance']['verified']);
        $apacheEvaluation = (new AdvisoryEvaluator())->evaluate($apacheInventory, AdvisoryCatalog::load());
        $apachePackageId = 'package-' . substr(hash('sha256', "libapache2-mod-php8.2\0" . '8.2.35-1~deb12u1' . "\0" . 'amd64'), 0, 20);
        self::assertContains($apachePackageId, array_column($apacheEvaluation['assessments'], 'subject_id'));
    }

    public function test_reinstall_required_dpkg_packages_remain_unknown_and_block_package_coverage(): void
    {
        $this->setDpkgPackageStatus($this->root, 'php8.2-fpm', 'hold reinstreq installed');
        file_put_contents(
            $this->root . '/var/lib/dpkg/status',
            "Package: php8.2-fpm\nStatus: hold reinstreq installed\nArchitecture: amd64\nVersion: 8.2.35-1~deb12u1\n\n",
        );

        $inventory = $this->collect();
        self::assertSame('incomplete', $inventory['package_inventory_state']);
        self::assertContains(
            ['name' => 'php8.2-fpm', 'version' => '8.2.35-1~deb12u1', 'architecture' => 'amd64'],
            $inventory['packages'],
        );
        self::assertFalse($inventory['workers'][0]['package_provenance']['verified']);
        $packageCoverage = array_values(array_filter(
            $inventory['coverage'],
            static fn(array $coverage): bool => $coverage['check_id'] === 'runtime.packages',
        ));
        self::assertCount(1, $packageCoverage);
        self::assertSame('blocked', $packageCoverage[0]['status']);
        self::assertNotNull($packageCoverage[0]['gap']);

        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());
        $packageId = 'package-' . substr(hash('sha256', "php8.2-fpm\0" . '8.2.35-1~deb12u1' . "\0" . 'amd64'), 0, 20);
        $packageAssessments = array_values(array_filter(
            $evaluation['assessments'],
            static fn(array $assessment): bool => $assessment['subject_id'] === $packageId,
        ));
        self::assertNotEmpty($packageAssessments);
        foreach ($packageAssessments as $assessment) {
            self::assertSame('unknown', $assessment['verdict']);
        }
    }

    public function test_not_installed_dpkg_rows_do_not_block_installed_package_coverage(): void
    {
        $this->appendDpkgPackageQueryRow($this->root, "php\t\tunknown ok not-installed\tall");

        $inventory = $this->collect();
        self::assertSame('attempted', $inventory['package_inventory_state']);
        self::assertContains(
            ['name' => 'php8.2-fpm', 'version' => '8.2.35-1~deb12u1', 'architecture' => 'amd64'],
            $inventory['packages'],
        );
        $packageCoverage = array_values(array_filter(
            $inventory['coverage'],
            static fn(array $coverage): bool => $coverage['check_id'] === 'runtime.packages',
        ));
        self::assertCount(1, $packageCoverage);
        self::assertSame('attempted', $packageCoverage[0]['status']);
        self::assertNull($packageCoverage[0]['gap']);

        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());
        $packageId = 'package-' . substr(hash('sha256', "php8.2-fpm\0" . '8.2.35-1~deb12u1' . "\0" . 'amd64'), 0, 20);
        $fixedAssessments = array_values(array_filter(
            $evaluation['assessments'],
            static fn(array $assessment): bool => $assessment['subject_id'] === $packageId
                && str_contains($assessment['record_id'], 'CVE-2026-109619'),
        ));
        self::assertNotEmpty($fixedAssessments);
        self::assertSame('verified_fixed', $fixedAssessments[0]['verdict']);
    }

    public function test_transitional_dpkg_rows_block_package_coverage_and_never_verify_packages(): void
    {
        $this->setDpkgPackageStatus($this->root, 'php8.2-fpm', 'hold ok half-configured');

        $inventory = $this->collect();
        self::assertSame('incomplete', $inventory['package_inventory_state']);
        self::assertContains(
            ['name' => 'php8.2-cli', 'version' => '8.2.35-1~deb12u1', 'architecture' => 'amd64'],
            $inventory['packages'],
        );
        self::assertNotContains(
            ['name' => 'php8.2-fpm', 'version' => '8.2.35-1~deb12u1', 'architecture' => 'amd64'],
            $inventory['packages'],
        );
        self::assertFalse($inventory['workers'][0]['package_provenance']['verified']);

        $packageCoverage = array_values(array_filter(
            $inventory['coverage'],
            static fn(array $coverage): bool => $coverage['check_id'] === 'runtime.packages',
        ));
        self::assertCount(1, $packageCoverage);
        self::assertSame('blocked', $packageCoverage[0]['status']);
        self::assertNotNull($packageCoverage[0]['gap']);

        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());
        $packageId = 'package-' . substr(hash('sha256', "php8.2-fpm\0" . '8.2.35-1~deb12u1' . "\0" . 'amd64'), 0, 20);
        self::assertNotContains($packageId, array_column($evaluation['assessments'], 'subject_id'));
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

    public function test_synthetic_unversioned_apache_module_claimed_by_exactly_one_package_is_verified(): void
    {
        $inventory = $this->collectApache();
        $worker = $inventory['workers'][0];
        self::assertTrue($worker['apache_namespace_verified'] ?? false);
        $proof = $worker['package_provenance'];
        self::assertTrue($proof['verified']);
        self::assertSame('libapache2-mod-php8.2', $proof['package_name']);
        self::assertSame('8.2.35-1~deb12u1', $proof['package_version']);
        self::assertSame('/usr/lib/apache2/modules/libphp.so', $proof['executable_path']);
        self::assertSame('local_package_database', $proof['trust_boundary']);
        self::assertNotEmpty($proof['evidence_source_ids']);
        self::assertContains('fact.worker.1.package_provenance', array_column($inventory['facts'], 'fact_id'));
        self::assertContains(
            '/proc/self/ns/mnt,/proc/self/root,/proc/789/ns/mnt,/proc/789/root',
            array_column($inventory['sources'], 'locator'),
        );
    }

    /** @return iterable<string, array{string}> */
    public static function invalidApacheEvidence(): iterable
    {
        foreach ([
            'replaced-module', 'missing-checksum', 'ambiguous-ownership', 'package-version-mismatch',
            'package-not-installed', 'module-deleted', 'multiple-modules', 'unsupported-distro',
            'symlink-module', 'symlink-checksum', 'oversized-module', 'different-mount-namespace',
            'different-process-root',
        ] as $case) {
            yield $case => [$case];
        }
    }

    #[DataProvider('invalidApacheEvidence')]
    public function test_missing_ambiguous_or_replaced_apache_evidence_stays_unverified(string $case): void
    {
        $module = $this->apacheRoot . '/usr/lib/apache2/modules/libphp.so';
        $metadata = $this->apacheRoot . '/var/lib/dpkg/info/libapache2-mod-php8.2.md5sums';
        $status = $this->apacheRoot . '/var/lib/dpkg/status';
        if ($case === 'replaced-module') {
            file_put_contents($module, 'replacement', FILE_APPEND);
        } elseif ($case === 'missing-checksum') {
            unlink($metadata);
        } elseif ($case === 'ambiguous-ownership') {
            copy($metadata, $this->apacheRoot . '/var/lib/dpkg/info/libapache2-mod-php8.3.md5sums');
            file_put_contents(
                $status,
                "Package: libapache2-mod-php8.2\nStatus: install ok installed\nArchitecture: amd64\nVersion: 8.2.35-1~deb12u1\n"
                . "\nPackage: libapache2-mod-php8.3\nStatus: install ok installed\nArchitecture: amd64\nVersion: 8.3.6-1~deb12u1\n",
            );
            file_put_contents(
                $this->apacheRoot . '/commands.json',
                '{"commands":{"dpkg-packages":{"exit_code":0,"stdout":"libapache2-mod-php8.2\\t8.2.35-1~deb12u1\\tinstall ok installed\\tamd64\\nlibapache2-mod-php8.3\\t8.3.6-1~deb12u1\\tinstall ok installed\\tamd64\\n"}}}',
            );
        } elseif ($case === 'package-version-mismatch') {
            file_put_contents($status, "Package: libapache2-mod-php8.2\nStatus: install ok installed\nArchitecture: amd64\nVersion: 8.2.34-1~deb12u1\n");
        } elseif ($case === 'package-not-installed') {
            file_put_contents($status, "Package: libapache2-mod-php8.2\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 8.2.35-1~deb12u1\n");
            $this->setApacheDpkgPackageQueryStatus('deinstall ok config-files');
        } elseif ($case === 'module-deleted') {
            file_put_contents(
                $this->apacheRoot . '/proc/789/maps',
                "7f000000-7f001000 r-xp 00000000 08:01 12345 /usr/lib/apache2/modules/libphp.so (deleted)\n",
            );
        } elseif ($case === 'multiple-modules') {
            copy($module, $this->apacheRoot . '/usr/lib/apache2/modules/libphp8.2.so');
            file_put_contents(
                $this->apacheRoot . '/proc/789/maps',
                "7f000000-7f001000 r-xp 00000000 08:01 12345 /usr/lib/apache2/modules/libphp.so\n"
                . "7f002000-7f003000 r-xp 00000000 08:01 12346 /usr/lib/apache2/modules/libphp8.2.so\n",
            );
        } elseif ($case === 'unsupported-distro') {
            file_put_contents($this->apacheRoot . '/etc/os-release', "ID=alpine\nVERSION_ID=3.23\n");
        } elseif ($case === 'symlink-module') {
            rename($module, $module . '.actual');
            symlink($module . '.actual', $module);
        } elseif ($case === 'symlink-checksum') {
            rename($metadata, $metadata . '.actual');
            symlink($metadata . '.actual', $metadata);
        } elseif ($case === 'oversized-module') {
            $file = fopen($module, 'r+');
            self::assertIsResource($file);
            ftruncate($file, 33_554_433);
            fclose($file);
        } elseif ($case === 'different-mount-namespace') {
            unlink($this->apacheRoot . '/proc/789/ns/mnt');
            symlink('mnt:[4026532999]', $this->apacheRoot . '/proc/789/ns/mnt');
        } elseif ($case === 'different-process-root') {
            mkdir($this->apacheRoot . '/alternate-process-root');
            unlink($this->apacheRoot . '/proc/789/root');
            symlink($this->apacheRoot . '/alternate-process-root', $this->apacheRoot . '/proc/789/root');
        }

        $worker = $this->collectApache()['workers'][0];
        $proof = $worker['package_provenance'];
        self::assertFalse($proof['verified']);
        if (in_array($case, ['different-mount-namespace', 'different-process-root'], true)) {
            self::assertSame('worker_namespace_identity_unverified', $proof['reason']);
            self::assertFalse($worker['apache_namespace_verified'] ?? true);
        }
    }

    public function test_residual_dpkg_rows_are_not_installed_package_subjects(): void
    {
        file_put_contents(
            $this->apacheRoot . '/var/lib/dpkg/status',
            "Package: libapache2-mod-php8.2\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 8.2.35-1~deb12u1\n",
        );
        $this->setApacheDpkgPackageQueryStatus('deinstall ok config-files');

        $inventory = $this->collectApache();
        self::assertSame([], $inventory['packages']);

        $packageId = 'package-' . substr(hash('sha256', "libapache2-mod-php8.2\0" . '8.2.35-1~deb12u1' . "\0" . 'amd64'), 0, 20);
        $evaluation = (new AdvisoryEvaluator())->evaluate($inventory, AdvisoryCatalog::load());
        $assessedSubjectIds = array_column($evaluation['assessments'], 'subject_id');
        self::assertNotContains($packageId, $assessedSubjectIds);
    }

    public function test_apache_module_provenance_is_cached_per_path_across_worker_processes(): void
    {
        $module = $this->apacheRoot . '/usr/lib/apache2/modules/libphp.so';
        $file = fopen($module, 'r+');
        self::assertIsResource($file);
        ftruncate($file, 8_388_608);
        fclose($file);
        file_put_contents(
            $this->apacheRoot . '/var/lib/dpkg/info/libapache2-mod-php8.2.md5sums',
            md5_file($module) . "  usr/lib/apache2/modules/libphp.so\n",
        );
        $stat = file_get_contents($this->apacheRoot . '/proc/789/stat');
        self::assertIsString($stat);
        for ($pid = 790; $pid < 805; ++$pid) {
            $this->copyDirectory($this->apacheRoot . '/proc/789', $this->apacheRoot . '/proc/' . $pid);
            file_put_contents($this->apacheRoot . '/proc/' . $pid . '/stat', preg_replace('/\A789 /', (string) $pid . ' ', $stat));
        }
        $workers = $this->collectApache()['workers'];
        self::assertCount(16, $workers);
        // Without per-path caching, the shared 64MiB hash budget would only cover ~8 of these
        // 16 workers (each independently hashing the same 8MiB module); caching proves every
        // worker resolves from one shared lookup instead of re-hashing the identical file.
        self::assertCount(16, array_filter($workers, static fn(array $worker): bool => $worker['package_provenance']['verified']));
    }

    /** @return RuntimeInventory */
    private function collect(): array
    {
        return (new RuntimeInventoryCollector(new FixtureProcessRunner($this->root), $this->root, '2026-10-26T00:00:00Z'))->collect();
    }

    /** @return RuntimeInventory */
    private function collectApache(): array
    {
        return (new RuntimeInventoryCollector(new FixtureProcessRunner($this->apacheRoot), $this->apacheRoot, '2026-10-26T00:00:00Z'))->collect();
    }

    private function setApacheDpkgPackageQueryStatus(string $status): void
    {
        $this->setDpkgPackageStatus($this->apacheRoot, 'libapache2-mod-php8.2', $status);
    }

    private function setDpkgPackageStatus(string $root, string $packageName, string $status): void
    {
        $commandsPath = $root . '/commands.json';
        $commandsData = json_decode((string) file_get_contents($commandsPath), true, 16, JSON_THROW_ON_ERROR);
        self::assertIsArray($commandsData);
        $commands = $commandsData['commands'] ?? null;
        self::assertIsArray($commands);
        $packageQuery = $commands['dpkg-packages'] ?? null;
        self::assertIsArray($packageQuery);
        $output = $packageQuery['stdout'] ?? null;
        self::assertIsString($output);
        $lines = preg_split('/\r?\n/', trim($output)) ?: [];
        foreach ($lines as $index => $line) {
            $parts = explode("\t", $line);
            if (count($parts) === 4 && $parts[0] === $packageName) {
                $parts[2] = $status;
                $lines[$index] = implode("\t", $parts);
            }
        }
        $packageQuery['stdout'] = implode("\n", $lines) . "\n";
        $commands['dpkg-packages'] = $packageQuery;
        $commandsData['commands'] = $commands;
        file_put_contents($commandsPath, json_encode($commandsData, JSON_THROW_ON_ERROR));
    }

    private function appendDpkgPackageQueryRow(string $root, string $row): void
    {
        $commandsPath = $root . '/commands.json';
        $commandsData = json_decode((string) file_get_contents($commandsPath), true, 16, JSON_THROW_ON_ERROR);
        self::assertIsArray($commandsData);
        $commands = $commandsData['commands'] ?? null;
        self::assertIsArray($commands);
        $packageQuery = $commands['dpkg-packages'] ?? null;
        self::assertIsArray($packageQuery);
        $output = $packageQuery['stdout'] ?? null;
        self::assertIsString($output);
        $packageQuery['stdout'] = rtrim($output, "\r\n") . "\n" . $row . "\n";
        $commands['dpkg-packages'] = $packageQuery;
        $commandsData['commands'] = $commands;
        file_put_contents($commandsPath, json_encode($commandsData, JSON_THROW_ON_ERROR));
    }

    private function materializeApacheProcLinks(): void
    {
        foreach ([
            '/proc/789/ns/mnt',
            '/proc/self/ns/mnt',
        ] as $relativePath) {
            $path = $this->apacheRoot . $relativePath;
            $target = file_get_contents($path);
            self::assertIsString($target);
            self::assertNotSame('', trim($target));
            unlink($path);
            self::assertTrue(symlink(trim($target), $path));
        }
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
