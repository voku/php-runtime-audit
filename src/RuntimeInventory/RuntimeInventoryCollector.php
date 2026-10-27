<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\RuntimeInventory;

use DateTimeImmutable;
use DateTimeZone;
use RuntimeException;
use voku\PhpRuntimeAudit\Evidence\DuplicateJsonKeyGuard;

/**
 * Collects bounded local facts without contacting or changing the audited host.
 *
 * @phpstan-type RuntimeCli array{id: string, kind: 'cli', binary_path: string, version: string, sapi: 'cli', extensions: list<string>|null}
 * @phpstan-type RuntimePackage array{name: string, version: string}
 * @phpstan-import-type PackageProvenance from RuntimePackageProvenance
 * @phpstan-type RuntimeWorker array{id: string, pid: int, kind: 'fpm'|'apache', process_name: string|null, executable_path: string|null, executable_deleted: bool|null, version: string|null, apache_php_modules: list<string>|null, apache_php_module_deleted: bool|null, process_start_ticks_since_boot: int|null, package_provenance: PackageProvenance}
 * @phpstan-type RuntimeSource array{source_id: string, kind: string, locator: string, captured_at: string, captured_digest: string|null, current_digest: string|null, freshness: string}
 * @phpstan-type RuntimeFact array{fact_id: string, key: string, value: mixed, source_id: string}
 * @phpstan-type RuntimeConfigObservation array{value: string, file: string, context: string, configuration_root: string|null}
 * @phpstan-type RuntimeConfigSetting array{value: string|null, state: string, files: list<string>, observations: list<RuntimeConfigObservation>}
 * @phpstan-type RuntimeConfigSettings array{'session.upload_progress.enabled': RuntimeConfigSetting, 'session.serialize_handler': RuntimeConfigSetting, memory_limit: RuntimeConfigSetting, post_max_size: RuntimeConfigSetting, upload_max_filesize: RuntimeConfigSetting, fatal_error_backtraces: RuntimeConfigSetting}
 * @phpstan-type RuntimeSapiConfiguration array{cli: RuntimeConfigSettings, fpm: RuntimeConfigSettings, apache2: RuntimeConfigSettings}
 * @phpstan-type ProcessIdentity array{pid: int, command: string, start_ticks: int}
 * @phpstan-type RuntimeConfiguration array{'session.upload_progress.enabled': RuntimeConfigSetting, 'session.serialize_handler': RuntimeConfigSetting, memory_limit: RuntimeConfigSetting, post_max_size: RuntimeConfigSetting, upload_max_filesize: RuntimeConfigSetting, fatal_error_backtraces: RuntimeConfigSetting, configured_extensions: list<array{name: string, file: string}>|null}
 * @phpstan-type RuntimeCoverage array{check_id: string, status: 'attempted'|'blocked', evidence_ids: list<string>, gap: string|null}
 * @phpstan-type RuntimeConfigurationCollection array{configuration: RuntimeConfiguration, by_sapi: RuntimeSapiConfiguration}
 * @phpstan-type RuntimeInventory array{schema_version: '1.0', asset_id: string, observed_at: string, distribution: string|null, distribution_version: string|null, distribution_codename: string|null, container: bool|null, runtimes: list<RuntimeCli>, packages: list<RuntimePackage>, package_manager: string|null, package_inventory_state: string, workers: list<RuntimeWorker>, configuration: RuntimeConfiguration, configuration_by_sapi: RuntimeSapiConfiguration, sources: list<RuntimeSource>, facts: list<RuntimeFact>, coverage: list<RuntimeCoverage>}
 */
final class RuntimeInventoryCollector
{
    private const MAX_FILE_BYTES = 1_048_576;
    private const MAX_CONFIG_FILE_BYTES = 262_144;
    private const MAX_CONFIG_FILES = 64;
    private const MAX_CONFIG_TREE_ENTRIES = 2048;
    private const MAX_FPM_POOL_SECTIONS = 32;
    private const MAX_PROCESSES = 4096;
    private const MAX_WORKERS = 16;
    private const MAX_RUNTIME_DIRECTORY_ENTRIES = 2048;
    private const MAX_RUNTIME_COMMANDS = 128;
    private const MAX_PATH_ENTRIES = 64;
    private const MAX_PATH_BYTES = 8192;
    private const CONFIG_KEYS = [
        'session.upload_progress.enabled',
        'session.serialize_handler',
        'memory_limit',
        'post_max_size',
        'upload_max_filesize',
        'fatal_error_backtraces',
    ];

    /** @var list<RuntimeSource> */
    private array $sources = [];
    /** @var list<RuntimeFact> */
    private array $facts = [];
    /** @var array<string, string> */
    private array $sourceByLocator = [];
    /** @var array<string, ProcessResult> */
    private array $processResults = [];
    /** @var list<ProcessCommandSpec> */
    private array $phpCommands = [];
    private string $rootRealPath;
    private string $observedAt;
    private string $workerDiscoveryState = 'unknown';
    private bool $workerDiscoveryTruncated = false;
    private bool $workerDiscoveryIncomplete = false;
    private bool $runtimeDiscoveryTruncated = false;
    private bool $runtimeDiscoveryIncomplete = false;
    private int $pathCandidateCount = 0;
    private bool $packageInventoryTruncated = false;
    private bool $configurationDiscoveryIncomplete = false;
    private int $configurationFilesFound = 0;

    public function __construct(
        private readonly ProcessRunner $processRunner,
        private readonly string $root = '/',
        ?string $observedAt = null,
        private readonly ?string $pathValue = null,
    ) {
        $rootRealPath = realpath($root);
        if ($rootRealPath === false || !is_dir($rootRealPath)) {
            throw new RuntimeException('Inventory root must be an existing directory.');
        }
        $this->rootRealPath = rtrim($rootRealPath, DIRECTORY_SEPARATOR) ?: DIRECTORY_SEPARATOR;
        $this->observedAt = $observedAt ?? (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d\TH:i:s\Z');
    }

    /** @return RuntimeInventory */
    public function collect(): array
    {
        $this->facts = [];
        $this->sources = [];
        $this->sourceByLocator = [];
        $this->processResults = [];
        $this->phpCommands = [];
        $this->workerDiscoveryState = 'unknown';
        $this->workerDiscoveryTruncated = false;
        $this->workerDiscoveryIncomplete = false;
        $this->runtimeDiscoveryTruncated = false;
        $this->runtimeDiscoveryIncomplete = false;
        $this->pathCandidateCount = 0;
        $this->packageInventoryTruncated = false;
        $this->configurationDiscoveryIncomplete = false;
        $this->configurationFilesFound = 0;

        $osRelease = $this->readFile('/etc/os-release', 65_536);
        $osSource = $this->addSource('file', '/etc/os-release', $osRelease);
        $os = $this->parseOsRelease($osRelease);
        foreach ([
            'ID' => 'os.id',
            'VERSION_ID' => 'os.version_id',
            'VERSION_CODENAME' => 'os.version_codename',
            'PRETTY_NAME' => 'os.pretty_name',
            'ID_LIKE' => 'os.id_like',
        ] as $key => $factKey) {
            $this->addFact($factKey, $os[$key] ?? null, $osSource);
        }

        $container = $this->containerEvidence();
        $containerSource = $this->addSource('other', '/.dockerenv, /run/.containerenv, /proc/1/cgroup', $container['evidence']);
        $this->addFact('container.detected', $container['detected'], $containerSource);

        $this->collectCommands();
        $runtimes = $this->collectCliRuntimes();
        $packageState = $this->collectPackages();
        $workers = $this->collectWorkers($packageState['manager'], $packageState['packages'], $os['ID'] ?? null);
        $configurationState = $this->collectConfiguration();
        $configuration = $configurationState['configuration'];
        $coverage = $this->buildCoverage($runtimes, $packageState, $workers, $configuration);

        return [
            'schema_version' => '1.0',
            'asset_id' => 'local-host',
            'observed_at' => $this->observedAt,
            'distribution' => $os['ID'] ?? null,
            'distribution_version' => $os['VERSION_ID'] ?? null,
            'distribution_codename' => $os['VERSION_CODENAME'] ?? null,
            'container' => $container['detected'],
            'runtimes' => $runtimes,
            'packages' => $packageState['packages'],
            'package_manager' => $packageState['manager'],
            'package_inventory_state' => $packageState['state'],
            'workers' => $workers,
            'configuration' => $configuration,
            'configuration_by_sapi' => $configurationState['by_sapi'],
            'sources' => $this->sources,
            'facts' => $this->facts,
            'coverage' => $coverage,
        ];
    }

    /** @return array<string, string> */
    private function parseOsRelease(?string $content): array
    {
        if ($content === null) {
            return [];
        }
        $values = [];
        $conflicts = [];
        foreach (preg_split('/\r?\n/', $content) ?: [] as $line) {
            if (preg_match('/\A([A-Z][A-Z0-9_]*)=(.*)\z/', trim($line), $matches) !== 1) {
                continue;
            }
            $value = trim($matches[2]);
            if (strlen($value) >= 2 && (($value[0] === '"' && str_ends_with($value, '"')) || ($value[0] === "'" && str_ends_with($value, "'")))) {
                $value = substr($value, 1, -1);
            }
            $key = $matches[1];
            if (strlen($value) > 256 || preg_match('/[\x00-\x1F\x7F]/', $value) === 1 || isset($conflicts[$key])) {
                continue;
            }
            if (isset($values[$key]) && $values[$key] !== $value) {
                unset($values[$key]);
                $conflicts[$key] = true;
                continue;
            }
            $values[$key] = $value;
        }

        return $values;
    }

    /** @return array{detected: bool|null, evidence: string} */
    private function containerEvidence(): array
    {
        $signals = [];
        foreach (['/.dockerenv', '/run/.containerenv'] as $marker) {
            if ($this->isFile($marker)) {
                $signals[] = $marker;
            }
        }
        $cgroup = $this->readFile('/proc/1/cgroup', 65_536);
        if ($cgroup !== null && preg_match('/(?:docker|kubepods|containerd|libpod|podman|lxc)/i', $cgroup) === 1) {
            $signals[] = '/proc/1/cgroup:container-token';
        }

        return ['detected' => $signals === [] ? null : true, 'evidence' => implode(',', $signals)];
    }

    private function collectCommands(): void
    {
        $commands = ProcessCommand::cases();
        $knownPaths = [];
        foreach ($commands as $command) {
            if ($command->isPhpCli() || $command->isFpm()) {
                $knownPaths[$command->executablePath()] = true;
                $this->phpCommands[] = $command;
            }
        }
        $pathDirectories = $this->pathDirectories();
        foreach ($this->discoverPhpCommands(array_keys($knownPaths), $pathDirectories) as $command) {
            $commands[] = $command;
            $this->phpCommands[] = $command;
        }

        foreach ($commands as $command) {
            $path = $command->executablePath();
            if (!$this->isFile($path) || is_link($this->path($path))) {
                continue;
            }
            $result = $this->processRunner->run($command);
            if ($command instanceof DiscoveredPhpCommand && !$result->succeeded()) {
                $this->runtimeDiscoveryIncomplete = true;
            }
            $this->processResults[$command->id()] = $result;
            $source = $this->addSource(
                $command instanceof ProcessCommand && in_array($command, [ProcessCommand::DpkgPackages, ProcessCommand::RpmPackages, ProcessCommand::ApkPackages], true)
                    ? 'package_database'
                    : 'runtime_report',
                'argv:' . $command->id(),
                $result->stdout,
            );
            if ($command instanceof DiscoveredPhpCommand) {
                $this->addFact('command.' . $command->id() . '.path', $path, $source);
            }
            $this->addFact('command.' . $command->id() . '.result', [
                'succeeded' => $result->succeeded(),
                'exit_code' => $result->exitCode,
                'timed_out' => $result->timedOut,
                'truncated' => $result->truncated,
                'error_category' => $this->commandErrorCategory($result),
            ], $source);
        }
        $discoverySource = $this->addSource('other', 'runtime-command-discovery', json_encode([
            'truncated' => $this->runtimeDiscoveryTruncated,
            'incomplete' => $this->runtimeDiscoveryIncomplete,
            'candidate_count' => count($this->phpCommands),
            'path_directories_inspected' => count($pathDirectories),
        ], JSON_THROW_ON_ERROR));
        $this->addFact('runtime.discovery.truncated', $this->runtimeDiscoveryTruncated, $discoverySource);
        $this->addFact('runtime.discovery.incomplete', $this->runtimeDiscoveryIncomplete, $discoverySource);
        $this->addFact('runtime.discovery.path_directories_inspected', count($pathDirectories), $discoverySource);
        $this->addFact('runtime.discovery.path_candidate_count', $this->pathCandidateCount, $discoverySource);
    }

    /**
     * Find versioned CLI/FPM names in a finite set of system directories. Remi's
     * side-by-side layout is handled by inspecting only known versioned roots.
     *
     * @param list<string> $knownPaths
     * @param list<string> $pathDirectories
     * @return list<DiscoveredPhpCommand>
     */
    private function discoverPhpCommands(array $knownPaths, array $pathDirectories): array
    {
        $known = array_fill_keys($knownPaths, true);
        $found = [];
        $visited = 0;
        foreach (['/usr/bin', '/usr/local/bin', '/usr/sbin', '/usr/local/sbin'] as $directory) {
            $this->scanRuntimeDirectory($directory, $directory, $known, $found, $visited);
        }
        foreach ($pathDirectories as $directory) {
            if ($this->isSupportedRuntimeDirectory($directory)) {
                continue;
            }
            $this->scanRuntimeDirectory($directory, $directory, $known, $found, $visited, $pathDirectories, false);
        }

        $remiRoot = $this->path('/opt/remi');
        if (is_link($remiRoot)) {
            $this->runtimeDiscoveryIncomplete = true;
        } elseif (is_dir($remiRoot)) {
            try {
                foreach (new \DirectoryIterator($remiRoot) as $entry) {
                    if ($entry->isDot()) {
                        continue;
                    }
                    if (++$visited > self::MAX_RUNTIME_DIRECTORY_ENTRIES) {
                        $this->runtimeDiscoveryTruncated = true;
                        break;
                    }
                    if ($entry->isLink()) {
                        if (preg_match('/\Aphp[0-9]{2,3}\z/', $entry->getFilename()) === 1) {
                            $this->runtimeDiscoveryIncomplete = true;
                        }
                        continue;
                    }
                    if (!$entry->isDir() || preg_match('/\Aphp[0-9]{2,3}\z/', $entry->getFilename()) !== 1) {
                        continue;
                    }
                    $prefix = '/opt/remi/' . $entry->getFilename() . '/root/usr';
                    $this->scanRuntimeDirectory($prefix . '/bin', $prefix . '/bin', $known, $found, $visited);
                    $this->scanRuntimeDirectory($prefix . '/sbin', $prefix . '/sbin', $known, $found, $visited);
                    if (count($found) >= self::MAX_RUNTIME_COMMANDS) {
                        $this->runtimeDiscoveryTruncated = true;
                        break;
                    }
                }
            } catch (\Throwable) {
                $this->runtimeDiscoveryIncomplete = true;
            }
        }

        return array_values($found);
    }

    /** @return list<string> */
    private function pathDirectories(): array
    {
        $value = $this->pathValue ?? getenv('PATH');
        if (!is_string($value) || $value === '') {
            $this->runtimeDiscoveryIncomplete = true;
            return [];
        }
        if (strlen($value) > self::MAX_PATH_BYTES) {
            $this->runtimeDiscoveryTruncated = true;
            $this->runtimeDiscoveryIncomplete = true;
            $value = substr($value, 0, self::MAX_PATH_BYTES);
        }

        $entries = explode(PATH_SEPARATOR, $value);
        if (count($entries) > self::MAX_PATH_ENTRIES) {
            $this->runtimeDiscoveryTruncated = true;
            $this->runtimeDiscoveryIncomplete = true;
            $entries = array_slice($entries, 0, self::MAX_PATH_ENTRIES);
        }

        $directories = [];
        foreach ($entries as $entry) {
            if ($entry === '' || strlen($entry) > 512 || !str_starts_with($entry, '/')
                || preg_match('/[\x00-\x1F\x7F]/', $entry) === 1) {
                $this->runtimeDiscoveryIncomplete = true;
                continue;
            }
            $segments = explode('/', trim($entry, '/'));
            if (in_array('.', $segments, true) || in_array('..', $segments, true)) {
                $this->runtimeDiscoveryIncomplete = true;
                continue;
            }
            $directory = rtrim($entry, '/') ?: '/';
            if (isset($directories[$directory])) {
                continue;
            }
            $directories[$directory] = true;
        }

        return array_keys($directories);
    }

    /**
     * @param array<string, true> $known
     * @param array<string, DiscoveredPhpCommand> $found
     * @param list<string> $pathDirectories
     */
    private function scanRuntimeDirectory(
        string $absoluteDirectory,
        string $commandDirectory,
        array $known,
        array &$found,
        int &$visited,
        array $pathDirectories = [],
        bool $probeCommands = true,
    ): void {
        $directory = $this->path($absoluteDirectory);
        if (is_link($directory)) {
            $this->runtimeDiscoveryIncomplete = true;
            return;
        }
        if (!is_dir($directory)) {
            return;
        }
        $realDirectory = realpath($directory);
        if ($realDirectory === false || !$this->withinRoot($realDirectory) || !is_dir($realDirectory)) {
            $this->runtimeDiscoveryIncomplete = true;
            return;
        }
        try {
            foreach (new \DirectoryIterator($realDirectory) as $entry) {
                if ($entry->isDot()) {
                    continue;
                }
                if (++$visited > self::MAX_RUNTIME_DIRECTORY_ENTRIES) {
                    $this->runtimeDiscoveryTruncated = true;
                    return;
                }
                $name = $entry->getFilename();
                $kind = preg_match('/\Aphp(?:[0-9]+(?:\.[0-9]+){0,2})?\z/', $name) === 1
                    ? 'cli'
                    : (preg_match('/\Aphp-fpm(?:[0-9]+(?:\.[0-9]+){0,2})?\z/', $name) === 1 ? 'fpm' : null);
                if ($kind === null) {
                    continue;
                }
                $path = $commandDirectory . '/' . $name;
                if ($entry->isLink()) {
                    $this->runtimeDiscoveryIncomplete = true;
                    continue;
                }
                if (!$entry->isFile() || isset($known[$path]) || isset($found[$path])) {
                    continue;
                }
                if (!$probeCommands) {
                    $this->recordUnprobedPathCandidate($path, $kind);
                    continue;
                }
                if (count($found) >= self::MAX_RUNTIME_COMMANDS) {
                    $this->runtimeDiscoveryTruncated = true;
                    return;
                }
                try {
                    $found[$path] = DiscoveredPhpCommand::fromPath($path, $kind, $pathDirectories);
                } catch (\InvalidArgumentException) {
                    $this->runtimeDiscoveryIncomplete = true;
                }
            }
        } catch (\Throwable) {
            $this->runtimeDiscoveryIncomplete = true;
        }
    }

    private function isSupportedRuntimeDirectory(string $directory): bool
    {
        return preg_match('~\A/(?:usr/bin|usr/local/bin|usr/sbin|usr/local/sbin|opt/remi/php[0-9]{2,3}/root/usr/(?:bin|sbin))\z~', $directory) === 1;
    }

    private function recordUnprobedPathCandidate(string $path, string $kind): void
    {
        $this->runtimeDiscoveryIncomplete = true;
        ++$this->pathCandidateCount;
        $source = $this->addSource('other', 'path-candidate:' . $path, $path);
        $basename = basename($path);
        $versionHint = null;
        $pattern = $kind === 'cli' ? '/\Aphp([0-9]+\.[0-9]+)\z/' : '/\Aphp-fpm([0-9]+\.[0-9]+)\z/';
        if (preg_match($pattern, $basename, $matches) === 1) {
            $versionHint = $matches[1];
        }
        $this->addFact('runtime.discovery.path_candidate.' . $this->pathCandidateCount, [
            'path' => $path,
            'kind' => $kind,
            'version_hint' => $versionHint,
            'executable' => is_executable($this->path($path)),
            'execution' => 'not_attempted_untrusted_path',
        ], $source);
    }

    private function commandErrorCategory(ProcessResult $result): ?string
    {
        // Match only fixed runner messages; arbitrary error and stderr text stays private.
        return match (true) {
            $result->succeeded() => null,
            $result->error === 'network isolation is unavailable; command was not executed' => 'network_isolation_unavailable',
            $result->error === 'network isolation or isolated command failed; facts are unavailable' => 'network_isolation_or_query_failed',
            $result->timedOut => 'timed_out',
            $result->truncated => 'output_truncated',
            $result->error !== null || $result->exitCode === null => 'execution_unavailable',
            default => 'query_failed',
        };
    }

    /** @return list<RuntimeCli> */
    private function collectCliRuntimes(): array
    {
        $runtimes = [];
        foreach ($this->phpCommands as $command) {
            if (!$command->isPhpCli()) {
                continue;
            }
            $result = $this->processResults[$command->id()] ?? null;
            if ($result === null || !$result->succeeded()) {
                continue;
            }
            try {
                DuplicateJsonKeyGuard::assertNoDuplicates($result->stdout);
                $data = json_decode($result->stdout, true, 8, JSON_THROW_ON_ERROR);
            } catch (\Throwable) {
                continue;
            }
            if (!is_array($data) || !is_string($data['version'] ?? null) || !is_string($data['sapi'] ?? null)) {
                continue;
            }
            $version = self::safePhpVersion($data['version']);
            $sapi = self::safeToken($data['sapi'], 32);
            if ($version === null || $sapi === null || $sapi !== 'cli') {
                continue;
            }
            $extensions = $this->safeExtensions($data['extensions'] ?? null);
            $sourceId = $this->sourceIdFor('argv:' . $command->id());
            $runtime = [
                'id' => 'cli-' . substr(hash('sha256', $command->executablePath()), 0, 20),
                'kind' => 'cli',
                'binary_path' => $command->executablePath(),
                'version' => $version,
                'sapi' => $sapi,
                'extensions' => $extensions,
            ];
            $runtimes[] = $runtime;
            $prefix = 'runtime.cli.' . count($runtimes);
            $this->addFact($prefix . '.version', $version, $sourceId);
            $this->addFact($prefix . '.id', $runtime['id'], $sourceId);
            $this->addFact($prefix . '.sapi', $sapi, $sourceId);
            $this->addFact($prefix . '.binary_path', $command->executablePath(), $sourceId);
            $this->addFact($prefix . '.extensions', $extensions, $sourceId);
        }

        return $runtimes;
    }

    /** @return array{manager: string|null, state: string, packages: list<array{name: string, version: string}>} */
    private function collectPackages(): array
    {
        $manager = null;
        $command = null;
        if ($this->isFile('/var/lib/dpkg/status')) {
            $manager = 'dpkg';
            $command = ProcessCommand::DpkgPackages;
        } elseif ($this->isFile('/usr/lib/sysimage/rpm/rpmdb.sqlite')
            || $this->isFile('/var/lib/rpm/rpmdb.sqlite')
            || $this->isFile('/var/lib/rpm/Packages')) {
            $manager = 'rpm';
            $command = ProcessCommand::RpmPackages;
        } elseif ($this->isFile('/lib/apk/db/installed')) {
            $manager = 'apk';
            $command = ProcessCommand::ApkPackages;
        }

        if ($manager === null) {
            $source = $this->addSource('package_database', 'package-database:unknown', null);
            $this->addFact('packages.manager', null, $source);
            $this->addFact('packages.state', 'unknown', $source);
            return ['manager' => null, 'state' => 'unknown', 'packages' => []];
        }

        $result = $this->processResults[$command->id()] ?? null;
        if ($result === null || !$result->succeeded()) {
            $source = $this->sourceIdFor('argv:' . $command->id());
            $this->addFact('packages.manager', $manager, $source);
            $this->addFact('packages.state', 'unknown', $source);
            return ['manager' => $manager, 'state' => 'unknown', 'packages' => []];
        }

        $packages = [];
        foreach (preg_split('/\r?\n/', trim($result->stdout)) ?: [] as $line) {
            if ($manager === 'apk') {
                $parts = preg_split('/-(?=[0-9]+\.[0-9]+)/', trim($line), 2);
                if (!is_array($parts) || count($parts) !== 2) {
                    continue;
                }
            } else {
                $parts = explode("\t", $line);
                if (count($parts) < 2) {
                    continue;
                }
            }
            $name = self::safeToken(trim($parts[0]), 128);
            $version = self::safeToken(trim($parts[1]), 256);
            if ($name === null || $version === null || !self::isPhpPackageName($name)) {
                continue;
            }
            $packages[] = ['name' => $name, 'version' => $version];
        }
        $source = $this->sourceIdFor('argv:' . $command->id());
        $this->addFact('packages.state', 'attempted', $source);
        $this->addFact('packages.manager', $manager, $source);
        $this->addFact('packages.inventory_count', count($packages), $source);
        $this->packageInventoryTruncated = count($packages) > 256;
        $this->addFact('packages.truncated', $this->packageInventoryTruncated, $source);
        foreach (array_slice($packages, 0, 256) as $index => $package) {
            $this->addFact('package.' . $index . '.name', $package['name'], $source);
            $this->addFact('package.' . $index . '.version', $package['version'], $source);
        }

        return ['manager' => $manager, 'state' => 'attempted', 'packages' => array_slice($packages, 0, 256)];
    }

    /**
     * @param list<RuntimePackage> $packages
     * @return list<RuntimeWorker>
     */
    private function collectWorkers(?string $manager, array $packages, ?string $distribution): array
    {
        $procPath = $this->path('/proc');
        $realProcPath = realpath($procPath);
        if ($realProcPath === false || is_link($procPath) || !$this->withinRoot($realProcPath) || !is_dir($realProcPath)) {
            $source = $this->addSource('other', '/proc', null);
            $this->addFact('workers.state', 'unknown', $source);
            return [];
        }

        try {
            $entries = new \DirectoryIterator($realProcPath);
        } catch (\Throwable) {
            $source = $this->addSource('other', '/proc', null);
            $this->addFact('workers.state', 'unknown', $source);
            return [];
        }

        $workers = [];
        $integrity = new RuntimePackageProvenance($this->rootRealPath);
        $seen = 0;
        foreach ($entries as $procEntry) {
            $entry = $procEntry->getFilename();
            if (preg_match('/\A[0-9]{1,10}\z/', $entry) !== 1) {
                continue;
            }
            if (++$seen > self::MAX_PROCESSES) {
                $this->workerDiscoveryTruncated = true;
                $source = $this->addSource('other', '/proc:process-limit', (string) self::MAX_PROCESSES);
                $this->addFact('workers.truncated', true, $source);
                break;
            }
            $base = '/proc/' . $entry;
            $comm = $this->readFile($base . '/comm', 4096);
            if ($comm === null) {
                $this->workerDiscoveryIncomplete = true;
                continue;
            }
            $name = trim($comm);
            $kind = str_starts_with($name, 'php-fpm') ? 'fpm' : (in_array($name, ['apache2', 'httpd'], true) ? 'apache' : null);
            if ($kind === null) {
                continue;
            }
            if (count($workers) >= self::MAX_WORKERS) {
                $this->workerDiscoveryTruncated = true;
                $source = $this->addSource('other', '/proc:worker-limit', (string) self::MAX_WORKERS);
                $this->addFact('workers.truncated', true, $source);
                break;
            }

            $statBefore = $this->readFile($base . '/stat', 8192);
            $identityBefore = $statBefore === null ? null : $this->processIdentity($statBefore);
            $identityBeforeMatches = $this->identityMatches($identityBefore, (int) $entry, $name);
            $exeLink = @readlink($this->path($base . '/exe'));
            if (!is_string($exeLink)) {
                $exeLink = $this->readFile($base . '/exe', 1024);
            }
            // Alternate roots use actual within-root proc symlinks in offline integrity fixtures.
            if ($this->rootRealPath !== '/' && is_link($this->path($base . '/exe'))) {
                $resolvedExecutable = realpath($this->path($base . '/exe'));
                if (is_string($resolvedExecutable) && $this->withinRoot($resolvedExecutable)) {
                    $exeLink = substr($resolvedExecutable, strlen($this->rootRealPath));
                }
            }
            $executableCandidate = is_string($exeLink) ? self::safeExecutablePath($exeLink) : null;
            $deletedCandidate = is_string($exeLink) ? str_ends_with($exeLink, ' (deleted)') : null;
            $processExecutableMatches = $kind !== 'fpm'
                || $this->fpmProcessNameMatchesExecutable($name, $executableCandidate);
            $cmdline = $kind === 'fpm' ? $this->readFile($base . '/cmdline', 4096) : null;
            $commandIdentity = $kind === 'fpm'
                ? $this->fpmCommandIdentity($cmdline, $executableCandidate)
                : 'unavailable';
            if ($kind === 'fpm') {
                $commandSource = $this->addSource('other', $base . '/cmdline', $cmdline);
                $this->addFact('worker.' . (count($workers) + 1) . '.command_identity', $commandIdentity, $commandSource);
            }
            $processExecutableMatches = $processExecutableMatches && $commandIdentity !== 'conflict';
            $maps = $kind === 'apache' ? $this->readFile($base . '/maps', self::MAX_FILE_BYTES) : null;
            $moduleEvidence = $maps === null ? ['paths' => null, 'deleted' => null] : $this->apachePhpModules($maps);
            $versionCandidate = $identityBeforeMatches && $processExecutableMatches && $kind === 'fpm'
                && $commandIdentity !== 'unknown' && $deletedCandidate === false
                ? $this->fpmVersionForPath($executableCandidate)
                : null;
            $apacheModulePath = $kind === 'apache' && is_array($moduleEvidence['paths']) && count($moduleEvidence['paths']) === 1
                ? $moduleEvidence['paths'][0]
                : null;
            $integrityResult = match (true) {
                $kind === 'fpm' && $versionCandidate !== null
                    => $integrity->check($distribution, $manager, $packages, $executableCandidate, $base),
                $kind === 'apache' && $identityBeforeMatches && $apacheModulePath !== null
                    => $integrity->checkApacheModule($distribution, $manager, $packages, $apacheModulePath, $moduleEvidence['deleted']),
                default => ['provenance' => RuntimePackageProvenance::unknown('runtime_identity_unavailable'), 'sources' => []],
            };
            $provenance = $integrityResult['provenance'];
            foreach ($integrityResult['sources'] as $integritySource) {
                $provenance['evidence_source_ids'][] = $this->addSource('file', $integritySource['locator'], $integritySource['content']);
            }
            $statAfter = $this->readFile($base . '/stat', 8192);
            $identityAfter = $statAfter === null ? null : $this->processIdentity($statAfter);
            $identityStable = $identityBeforeMatches
                && $processExecutableMatches
                && $this->sameProcessSnapshot($identityBefore, $identityAfter, (int) $entry, $name);
            if (!$identityStable) {
                $provenance['verified'] = false;
                $provenance['reason'] = 'process_identity_unstable';
            }
            $executable = $identityStable ? $executableCandidate : null;
            $deleted = $identityStable ? $deletedCandidate : null;
            $modules = $identityStable ? $moduleEvidence['paths'] : null;
            $moduleDeleted = $identityStable ? $moduleEvidence['deleted'] : null;
            $startTicks = $identityStable ? ($identityBefore['start_ticks'] ?? null) : null;
            $version = $identityStable ? $versionCandidate : null;
            $workerDetailsIncomplete = !$identityStable || !is_string($exeLink) || $executable === null;
            if ($kind === 'fpm' && $version === null) {
                $workerDetailsIncomplete = true;
            }
            if ($kind === 'apache' && ($maps === null || trim($maps) === '' || $moduleDeleted === true)) {
                $workerDetailsIncomplete = true;
            }
            if ($workerDetailsIncomplete) {
                $this->workerDiscoveryIncomplete = true;
            }
            $sourceContent = implode("\n", array_filter([$comm, $exeLink ?: '', $statBefore ?: '', $maps ?: '', $statAfter ?: '']));
            $source = $this->addSource('other', $base . '/comm,/exe,/stat,/maps', $sourceContent);
            $worker = [
                'id' => 'worker-' . (int) $entry . '-' . ($startTicks === null ? 'unknown' : $startTicks),
                'pid' => (int) $entry,
                'kind' => $kind,
                'process_name' => self::safeToken($name, 128),
                'executable_path' => $executable,
                'executable_deleted' => $deleted,
                'version' => $version,
                'apache_php_modules' => $modules,
                'apache_php_module_deleted' => $moduleDeleted,
                'process_start_ticks_since_boot' => $startTicks,
                'package_provenance' => $provenance,
            ];
            $workers[] = $worker;
            $prefix = 'worker.' . count($workers);
            $this->addFact($prefix . '.id', $worker['id'], $source);
            $this->addFact($prefix . '.kind', $kind, $source);
            $this->addFact($prefix . '.process_name', $worker['process_name'], $source);
            $this->addFact($prefix . '.executable_path', $executable, $source);
            $this->addFact($prefix . '.executable_deleted', $deleted, $source);
            $this->addFact($prefix . '.version', $version, $source);
            $this->addFact($prefix . '.apache_php_modules', $modules, $source);
            $this->addFact($prefix . '.apache_php_module_deleted', $moduleDeleted, $source);
            $this->addFact($prefix . '.start_ticks_since_boot', $startTicks, $source);
            $provenanceSource = $this->addSource('other', $base . ':package-provenance', json_encode($provenance, JSON_THROW_ON_ERROR));
            $this->addFact($prefix . '.package_provenance', $provenance, $provenanceSource);
        }
        $stateSource = $this->addSource('other', '/proc:worker-discovery', (string) count($workers));
        $this->workerDiscoveryState = match (true) {
            $this->workerDiscoveryIncomplete && $workers === [] => 'unknown',
            $this->workerDiscoveryIncomplete => 'partial',
            $workers === [] => 'none_detected',
            default => 'attempted',
        };
        if ($this->workerDiscoveryIncomplete) {
            $this->addFact('workers.incomplete', true, $stateSource);
        }
        $this->addFact('workers.state', $this->workerDiscoveryState, $stateSource);

        return $workers;
    }

    /**
     * @param list<RuntimeCli> $runtimes
     * @param array{manager: string|null, state: string, packages: list<RuntimePackage>} $packageState
     * @param list<RuntimeWorker> $workers
     * @param RuntimeConfiguration $configuration
     * @return list<RuntimeCoverage>
     */
    private function buildCoverage(array $runtimes, array $packageState, array $workers, array $configuration): array
    {
        $configurationFiles = $configuration['configured_extensions'] === null
            ? []
            : array_column($configuration['configured_extensions'], 'file');
        foreach (self::CONFIG_KEYS as $key) {
            $configurationFiles = array_merge($configurationFiles, $configuration[$key]['files']);
        }
        $configurationFiles = array_values(array_unique($configurationFiles));
        $workerGaps = [];
        if ($this->workerDiscoveryState === 'unknown') {
            $workerGaps[] = 'The local /proc process table could not be read completely; worker absence is unverified.';
        }
        if ($this->workerDiscoveryTruncated) {
            $workerGaps[] = 'The process or worker scan reached its configured limit; some workers may be omitted.';
        }
        if ($this->workerDiscoveryState === 'partial') {
            $workerGaps[] = 'Some process or worker details were inaccessible or incomplete; unobserved runtimes remain unknown.';
        }
        $phpRuntimeDetected = false;
        foreach ($workers as $worker) {
            if ($worker['kind'] === 'fpm'
                || ($worker['apache_php_modules'] !== null && $worker['apache_php_modules'] !== [])) {
                $phpRuntimeDetected = true;
            }
        }
        if (!$phpRuntimeDetected && $this->workerDiscoveryState !== 'unknown') {
            $workerGaps[] = 'No PHP-FPM process or Apache PHP module mapping was detected.';
        }
        foreach ($workers as $worker) {
            if ($worker['kind'] === 'fpm' && ($worker['version'] === null || $worker['executable_deleted'])) {
                $workerGaps[] = 'A PHP-FPM worker was found, but its active runtime version could not be resolved.';
            }
            if ($worker['kind'] === 'apache' && $worker['apache_php_modules'] === null) {
                $workerGaps[] = 'An Apache worker was found, but its loaded PHP module mapping could not be read.';
            } elseif ($worker['kind'] === 'apache' && $worker['apache_php_modules'] === []) {
                $workerGaps[] = 'An Apache worker was found, but no loaded libphp module was detected.';
            } elseif ($worker['kind'] === 'apache' && $worker['apache_php_modules'] !== []) {
                $workerGaps[] = 'An Apache PHP module path was found, but the mapped running module version is not established.';
            }
            if ($worker['process_start_ticks_since_boot'] === null) {
                $workerGaps[] = 'A worker start time could not be read, so its restart state is unverified.';
            }
        }
        $workerGap = $workerGaps === [] ? null : implode(' ', array_values(array_unique($workerGaps)));

        return [
            [
                'check_id' => 'runtime.cli',
                'status' => $runtimes === [] ? 'blocked' : 'attempted',
                'evidence_ids' => $runtimes === [] ? [] : $this->factIdsForPrefix('runtime.cli.'),
                'gap' => $runtimes === [] ? 'No allowlisted PHP CLI binary produced a valid runtime report.' : null,
            ],
            [
                'check_id' => 'runtime.packages',
                'status' => $packageState['state'] === 'attempted' && !$this->packageInventoryTruncated ? 'attempted' : 'blocked',
                'evidence_ids' => $this->factIdsForPrefix('packages.'),
                'gap' => $this->packageInventoryTruncated
                    ? 'The package inventory exceeded its configured record limit; omitted package subjects remain unknown.'
                    : ($packageState['state'] === 'attempted' ? null : 'No supported package database query produced a complete package inventory.'),
            ],
            [
                'check_id' => 'runtime.workers',
                'status' => $this->workerDiscoveryState === 'unknown' ? 'blocked' : 'attempted',
                'evidence_ids' => $this->factIdsForPrefix('workers.'),
                'gap' => $workerGap,
            ],
            [
                'check_id' => 'runtime.configuration',
                'status' => $this->configurationFilesFound === 0 || $this->configurationDiscoveryIncomplete ? 'blocked' : 'attempted',
                'evidence_ids' => $this->factIdsForPrefix('configuration.'),
                'gap' => $this->configurationFilesFound === 0
                    ? 'No supported PHP INI or FPM pool configuration files were accessible.'
                    : ($this->configurationDiscoveryIncomplete
                        ? 'Configuration discovery was bounded or incomplete; omitted or symlinked files remain unknown.'
                        : null),
            ],
            [
                'check_id' => 'runtime.discovery',
                'status' => $this->runtimeDiscoveryIncomplete || $this->runtimeDiscoveryTruncated ? 'blocked' : 'attempted',
                'evidence_ids' => $this->factIdsForPrefix('runtime.discovery.'),
                'gap' => $this->runtimeDiscoveryTruncated
                    ? 'Runtime binary discovery reached its configured PATH, directory, or command limit; additional PHP installations may be omitted.'
                    : ($this->runtimeDiscoveryIncomplete
                        ? 'One or more PATH entries, runtime directories, or candidate binaries could not be inspected safely; unobserved installations remain unknown.'
                        : null),
            ],
        ];
    }

    /** @return list<string> */
    private function factIdsForPrefix(string $prefix): array
    {
        $ids = [];
        foreach ($this->facts as $fact) {
            if (str_starts_with($fact['key'], $prefix)) {
                $ids[] = $fact['fact_id'];
            }
        }

        return $ids;
    }

    /** @return RuntimeConfigurationCollection */
    private function collectConfiguration(): array
    {
        $files = $this->configurationFiles();
        $this->configurationFilesFound = count($files);
        $values = [];
        $sapiValues = ['cli' => [], 'fpm' => [], 'apache2' => []];
        $extensions = [];
        $readableFiles = 0;
        foreach ($files as $file) {
            $contents = $this->readFile($file, self::MAX_CONFIG_FILE_BYTES);
            if ($contents === null) {
                $this->configurationDiscoveryIncomplete = true;
                continue;
            }
            ++$readableFiles;
            $source = $this->addSource('file', $file, $contents);
            $sapis = $this->configurationSapisForFile($file);
            $configurationRoot = in_array('fpm', $sapis, true) || in_array('apache2', $sapis, true)
                ? $this->configurationRoot($file)
                : null;
            $settingsByContext = $sapis === ['fpm'] && str_ends_with($file, '.conf')
                ? $this->parseSafeFpmPools($contents)
                : [['context' => 'global', 'settings' => $this->parseSafeIni($contents)]];
            foreach ($settingsByContext as $contextSettings) {
                $settings = $contextSettings['settings'];
                foreach ($settings as $name => $value) {
                    $entry = [
                        'value' => $value,
                        'file' => $file,
                        'context' => $contextSettings['context'],
                        'configuration_root' => $configurationRoot,
                        'source_id' => $source,
                    ];
                    $values[$name][] = $entry;
                    foreach ($sapis as $sapi) {
                        $sapiValues[$sapi][$name][] = $entry;
                    }
                }
            }
            foreach ($this->parseConfiguredExtensions($contents) as $extension) {
                $extensions[] = ['name' => $extension, 'file' => $file];
            }
        }

        /** @var RuntimeConfiguration $result */
        $result = [];
        foreach (self::CONFIG_KEYS as $name) {
            $entries = $values[$name] ?? [];
            $distinct = array_unique(array_column($entries, 'value'));
            $state = count($distinct) > 1
                ? 'conflict'
                : ($this->configurationDiscoveryIncomplete || $distinct === [] ? 'unknown' : 'observed');
            $value = $state === 'observed' ? $distinct[0] : null;
            $observations = array_map(
                static fn(array $entry): array => [
                    'value' => $entry['value'],
                    'file' => $entry['file'],
                    'context' => $entry['context'],
                    'configuration_root' => $entry['configuration_root'],
                ],
                $entries,
            );
            $result[$name] = [
                'value' => $value,
                'state' => $state,
                'files' => array_column($entries, 'file'),
                'observations' => $observations,
            ];
            $evidence = json_encode($result[$name], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            $sourceId = $this->addSource('other', 'configuration:' . $name, $evidence);
            $this->addFact('configuration.' . $name, $result[$name], $sourceId);
        }
        /** @var RuntimeSapiConfiguration $bySapi */
        $bySapi = [
            'cli' => $this->unknownConfigurationSettings(),
            'fpm' => $this->unknownConfigurationSettings(),
            'apache2' => $this->unknownConfigurationSettings(),
        ];
        foreach (['cli', 'fpm', 'apache2'] as $sapi) {
            foreach (self::CONFIG_KEYS as $name) {
                $entries = $sapiValues[$sapi][$name] ?? [];
                $distinct = array_unique(array_column($entries, 'value'));
                $state = count($distinct) > 1
                    ? 'conflict'
                    : ($this->configurationDiscoveryIncomplete || $distinct === [] ? 'unknown' : 'observed');
                $value = $state === 'observed' ? $distinct[0] : null;
                $observations = array_map(
                    static fn(array $entry): array => [
                        'value' => $entry['value'],
                        'file' => $entry['file'],
                        'context' => $entry['context'],
                        'configuration_root' => $entry['configuration_root'],
                    ],
                    $entries,
                );
                $bySapi[$sapi][$name] = [
                    'value' => $value,
                    'state' => $state,
                    'files' => array_column($entries, 'file'),
                    'observations' => $observations,
                ];
                $evidence = json_encode($bySapi[$sapi][$name], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
                $sourceId = $this->addSource('other', 'configuration:' . $sapi . ':' . $name, $evidence);
                $this->addFact(
                    'configuration.' . $sapi . '.' . $name,
                    $bySapi[$sapi][$name],
                    $sourceId,
                );
            }
        }
        $extensions = $readableFiles === 0 || $this->configurationDiscoveryIncomplete
            ? null
            : array_values(array_unique($extensions, SORT_REGULAR));
        $extensionEvidence = json_encode($extensions, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $extensionSource = $this->addSource('other', 'configuration:configured-extensions', $extensionEvidence);
        $this->addFact('configuration.configured_extensions', $extensions, $extensionSource);

        $result['configured_extensions'] = $extensions;

        return ['configuration' => $result, 'by_sapi' => $bySapi];
    }

    /** @return list<'cli'|'fpm'|'apache2'> */
    private function configurationSapisForFile(string $file): array
    {
        $path = '/' . trim(str_replace('\\', '/', $file), '/') . '/';
        if (str_contains($path, '/cli/')) {
            return ['cli'];
        }
        if (str_contains($path, '/fpm/')
            || str_contains($path, '/fpm.d/')
            || str_contains($path, '/php-fpm.d/')
            || str_contains($path, '/pool.d/')
            || str_ends_with($path, '/php-fpm.conf/')) {
            return ['fpm'];
        }
        if (str_contains($path, '/apache2/')) {
            return ['apache2'];
        }

        return ['cli', 'fpm', 'apache2'];
    }

    /** @return RuntimeConfigSettings */
    private function unknownConfigurationSettings(): array
    {
        $unknown = ['value' => null, 'state' => 'unknown', 'files' => [], 'observations' => []];

        return [
            'session.upload_progress.enabled' => $unknown,
            'session.serialize_handler' => $unknown,
            'memory_limit' => $unknown,
            'post_max_size' => $unknown,
            'upload_max_filesize' => $unknown,
            'fatal_error_backtraces' => $unknown,
        ];
    }

    /** @return list<string> */
    private function configurationFiles(): array
    {
        $candidates = [
            '/etc/php.ini', '/etc/php.d/php.ini', '/usr/local/etc/php/php.ini',
            '/usr/local/etc/php/conf.d/99-runtime-audit.ini',
            '/etc/php-fpm.conf', '/usr/local/etc/php-fpm.conf',
        ];
        foreach (['/etc/php', '/etc/opt/remi', '/usr/local/etc/php', '/etc/php.d', '/etc/php-fpm.d', '/usr/local/etc/php-fpm.d'] as $base) {
            $basePath = $this->path($base);
            if (is_link($basePath)) {
                $this->configurationDiscoveryIncomplete = true;
                continue;
            }
            if (!is_dir($basePath)) {
                continue;
            }
            $pendingDirectories = [$basePath];
            $visitedEntries = 0;
            while ($pendingDirectories !== [] && count($candidates) < self::MAX_CONFIG_FILES) {
                $directory = array_pop($pendingDirectories);
                if (is_link($directory)) {
                    $this->configurationDiscoveryIncomplete = true;
                    continue;
                }
                $realDirectory = realpath($directory);
                if ($realDirectory === false || !$this->withinRoot($realDirectory) || !is_dir($realDirectory)) {
                    $this->configurationDiscoveryIncomplete = true;
                    continue;
                }
                try {
                    $entries = new \DirectoryIterator($realDirectory);
                    foreach ($entries as $fileInfo) {
                        if ($fileInfo->isDot()) {
                            continue;
                        }
                        if (++$visitedEntries > self::MAX_CONFIG_TREE_ENTRIES) {
                            $this->configurationDiscoveryIncomplete = true;
                            break 2;
                        }
                        $path = $fileInfo->getPathname();
                        if ($fileInfo->isLink()) {
                            $entry = $fileInfo->getFilename();
                            if ($fileInfo->isDir()
                                || $entry === 'php.ini'
                                || $this->isConfigurationFragment($path, $entry)) {
                                $this->configurationDiscoveryIncomplete = true;
                            }
                            continue;
                        }
                        if ($fileInfo->isDir()) {
                            $pendingDirectories[] = $path;
                            continue;
                        }
                        if (!$fileInfo->isFile()) {
                            continue;
                        }
                        $entry = $fileInfo->getFilename();
                        $isConfig = $entry === 'php.ini' || $this->isConfigurationFragment($path, $entry);
                        if ($fileInfo->getSize() > self::MAX_CONFIG_FILE_BYTES) {
                            if ($isConfig) {
                                $this->configurationDiscoveryIncomplete = true;
                            }
                            continue;
                        }
                        if ($isConfig) {
                            $relative = substr($path, strlen($this->rootRealPath));
                            $candidates[] = '/' . ltrim(str_replace(DIRECTORY_SEPARATOR, '/', $relative), '/');
                            if (count($candidates) >= self::MAX_CONFIG_FILES) {
                                $this->configurationDiscoveryIncomplete = true;
                                break 2;
                            }
                        }
                    }
                } catch (\Throwable) {
                    $this->configurationDiscoveryIncomplete = true;
                }
            }
        }
        foreach (['/etc/php', '/usr/local/etc/php', '/etc/opt/remi'] as $base) {
            foreach (['cli/php.ini', 'fpm/php.ini', 'apache2/php.ini', 'php.ini'] as $suffix) {
                $candidates[] = rtrim($base, '/') . '/' . $suffix;
            }
        }
        $candidates = array_values(array_unique($candidates));
        sort($candidates, SORT_STRING);
        if (count($candidates) > self::MAX_CONFIG_FILES) {
            $this->configurationDiscoveryIncomplete = true;
            $candidates = array_slice($candidates, 0, self::MAX_CONFIG_FILES);
        }

        $files = [];
        foreach ($candidates as $candidate) {
            $path = $this->path($candidate);
            if (is_link($path)) {
                $this->configurationDiscoveryIncomplete = true;
                continue;
            }
            if ($this->isFile($candidate)) {
                $files[] = $candidate;
            }
        }

        return $files;
    }

    private function isConfigurationFragment(string $path, string $entry): bool
    {
        return preg_match('/\.(?:ini|conf)\z/', $entry) === 1
            && (
                str_contains($path, DIRECTORY_SEPARATOR . 'conf.d' . DIRECTORY_SEPARATOR)
                || str_contains($path, DIRECTORY_SEPARATOR . 'pool.d' . DIRECTORY_SEPARATOR)
                || str_contains($path, DIRECTORY_SEPARATOR . 'php.d' . DIRECTORY_SEPARATOR)
                || str_contains($path, DIRECTORY_SEPARATOR . 'php-fpm.d' . DIRECTORY_SEPARATOR)
            );
    }

    /** @return list<array{context: string, settings: array<string, string>}> */
    private function parseSafeFpmPools(string $contents): array
    {
        // Section identity must survive key normalization: each pool has its own values.
        // Keep admin/value namespaces separate because their precedence is not evaluated.
        $pools = [];
        $section = 'unscoped';
        foreach (preg_split('/\r?\n/', $contents) ?: [] as $lineNumber => $line) {
            if (str_starts_with(ltrim($line), '[')) {
                if (preg_match('/\A\s*\[([^\]\x00-\x1F\x7F]{1,128})\]\s*(?:[;#].*)?\z/', $line, $matches) === 1
                    && trim($matches[1]) !== '') {
                    $section = 'pool:' . trim($matches[1]);
                } else {
                    // Malformed headers must not merge later settings into a known pool.
                    $this->configurationDiscoveryIncomplete = true;
                    $section = 'unknown:' . $lineNumber;
                }
                if (!isset($pools[$section])) {
                    if (count($pools) >= self::MAX_FPM_POOL_SECTIONS) {
                        $this->configurationDiscoveryIncomplete = true;
                        break;
                    }
                    $pools[$section] = [];
                }
                continue;
            }
            $settings = $this->parseSafeIni($line);
            if ($settings === []) {
                continue;
            }
            if (!isset($pools[$section])) {
                if (count($pools) >= self::MAX_FPM_POOL_SECTIONS) {
                    $this->configurationDiscoveryIncomplete = true;
                    break;
                }
                $pools[$section] = [];
            }
            $kind = preg_match('/\A\s*(php_(?:admin_)?value)\[/i', $line, $matches) === 1
                ? strtolower($matches[1])
                : 'ini';
            foreach ($settings as $name => $value) {
                $pools[$section][$kind][$name] = $value;
            }
        }
        $contexts = [];
        foreach ($pools as $pool => $kinds) {
            foreach ($kinds as $settings) {
                $contexts[] = [
                    'context' => $pool === 'unscoped' ? 'global' : $pool,
                    'settings' => $settings,
                ];
            }
        }

        return $contexts;
    }

    private function configurationRoot(string $file): string
    {
        $normalized = '/' . trim(str_replace('\\', '/', $file), '/') . '/';
        if (preg_match('#\A(/etc/php/[^/]+/fpm)(?:/|\z)#', $normalized, $matches) === 1) {
            return $matches[1];
        }
        if (str_starts_with($normalized, '/usr/local/etc/php/')) {
            return '/usr/local/etc';
        }
        foreach (['/pool.d/', '/php-fpm.d/', '/fpm.d/', '/conf.d/', '/php.d/'] as $marker) {
            $position = strpos($normalized, $marker);
            if ($position !== false) {
                return rtrim(substr($normalized, 0, $position), '/');
            }
        }

        return dirname('/' . trim(str_replace('\\', '/', $file), '/'));
    }

    /** @return array<string, string> */
    private function parseSafeIni(string $contents): array
    {
        $wanted = array_fill_keys(self::CONFIG_KEYS, true);
        $settings = [];
        foreach (preg_split('/\r?\n/', $contents) ?: [] as $line) {
            $name = null;
            $rawValue = null;
            if (preg_match('/\A\s*([a-zA-Z0-9_.-]{1,64})\s*=\s*(.*?)\s*\z/', $line, $matches) === 1) {
                $name = strtolower($matches[1]);
                $rawValue = $matches[2];
            } elseif (preg_match('/\A\s*php_(?:admin_)?value\[([a-zA-Z0-9_.-]{1,64})\]\s*=\s*(.*?)\s*\z/i', $line, $matches) === 1) {
                $name = strtolower($matches[1]);
                $rawValue = $matches[2];
            }
            if ($name === null) {
                continue;
            }
            if (!isset($wanted[$name])) {
                continue;
            }
            $value = trim($rawValue);
            if (strlen($value) >= 2 && (($value[0] === '"' && str_ends_with($value, '"')) || ($value[0] === "'" && str_ends_with($value, "'")))) {
                $value = substr($value, 1, -1);
            } else {
                $value = trim(preg_split('/[;#]/', $value, 2)[0] ?? $value);
            }
            if (strlen($value) <= 128 && preg_match('/[\x00-\x1F\x7F]/', $value) !== 1) {
                $settings[$name] = $value;
            }
        }

        return $settings;
    }

    /** @return list<string> */
    private function parseConfiguredExtensions(string $contents): array
    {
        $extensions = [];
        foreach (preg_split('/\r?\n/', $contents) ?: [] as $line) {
            if (preg_match('/\A\s*(?:zend_)?extension\s*=\s*["\']?([^\s;"\']+)["\']?/', $line, $matches) !== 1) {
                continue;
            }
            $name = basename($matches[1]);
            $name = preg_replace('/\.(?:so|dll|dylib)\z/i', '', $name) ?? $name;
            if (preg_match('/\A[a-zA-Z0-9_-]{1,64}\z/', $name) === 1) {
                $extensions[] = strtolower($name);
            }
        }
        $extensions = array_values(array_unique($extensions));
        sort($extensions, SORT_STRING);

        return $extensions;
    }

    private function fpmVersionForPath(?string $path): ?string
    {
        if ($path === null) {
            return null;
        }
        foreach ($this->phpCommands as $command) {
            if (!$command->isFpm() || $command->executablePath() !== $path) {
                continue;
            }
            $result = $this->processResults[$command->id()] ?? null;
            if ($result === null || !$result->succeeded()) {
                return null;
            }
            if (preg_match('/\APHP\s+([0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z][A-Za-z0-9.+-]{0,31})?)\s+\(fpm-fcgi\)(?:\s+\(built:[^\r\n]{0,160}\))?\s*(?:\r?\n|\z)/', $result->stdout, $matches) === 1) {
                return self::safePhpVersion($matches[1]);
            }
        }

        return null;
    }

    /** @return 'matched'|'unavailable'|'conflict'|'unknown' */
    private function fpmCommandIdentity(?string $cmdline, ?string $executablePath): string
    {
        // argv is inspected in memory only; sources retain its digest, never arguments.
        if ($cmdline === null || $cmdline === '' || !str_ends_with($cmdline, "\0")) {
            return 'unknown';
        }
        $arguments = explode("\0", $cmdline);
        $argv0 = $arguments[0];
        if ($argv0 === '' || strlen($argv0) > 1024 || preg_match('/[\x00-\x1F\x7F]/', $argv0) === 1) {
            return 'unknown';
        }
        // FPM rewrites argv into a title and pads the original argument region with NULs.
        if (preg_match('/\Aphp-fpm: (?:master process \([^\r\n]{1,960}\)|pool [a-zA-Z0-9_.-]{1,128})\z/', $argv0) === 1
            && trim(substr($cmdline, strlen($argv0)), "\0") === '') {
            return 'unavailable';
        }
        $name = basename($argv0);
        if ($name !== 'php-fpm' && self::fpmProcessVersion($name) === null) {
            return 'unknown';
        }
        if (str_contains($argv0, '/')) {
            $path = self::safeExecutablePath($argv0);
            if ($path === null || $executablePath === null) {
                return 'unknown';
            }

            return $path === $executablePath ? 'matched' : 'conflict';
        }

        return $this->fpmProcessNameMatchesExecutable($name, $executablePath) ? 'matched' : 'conflict';
    }

    private function fpmProcessNameMatchesExecutable(string $processName, ?string $executablePath): bool
    {
        $processVersion = self::fpmProcessVersion(basename($processName));
        if ($processVersion === null) {
            return true;
        }

        $executableVersion = $executablePath === null
            ? null
            : self::fpmProcessVersion(basename($executablePath));

        return $executableVersion !== null && $processVersion === $executableVersion;
    }

    private static function fpmProcessVersion(string $name): ?string
    {
        if (preg_match('/\Aphp-fpm([0-9]+\.[0-9]{1,2}|[0-9]{2,3})\z/i', $name, $matches) !== 1) {
            return null;
        }
        if (preg_match('/\A([0-9]+)([0-9]{1,2})\z/', $matches[1], $compact) === 1) {
            return $compact[1] . '.' . $compact[2];
        }

        return $matches[1];
    }

    /** @return array{paths: list<string>|null, deleted: bool|null} */
    private function apachePhpModules(string $maps): array
    {
        $modules = [];
        $deleted = false;
        foreach (preg_split('/\r?\n/', $maps) ?: [] as $line) {
            if (preg_match('~(/[^\s]*libphp[^\s/]*\.so)(?:\s+\(deleted\))?(?:\s|$)~', $line, $matches) === 1) {
                $module = self::safeExecutablePath($matches[1]);
                if ($module !== null) {
                    $modules[] = $module;
                    $deleted = $deleted || str_contains($matches[0], '(deleted)');
                }
            }
        }
        $modules = array_values(array_unique($modules));
        sort($modules, SORT_STRING);

        return ['paths' => $modules, 'deleted' => $deleted];
    }

    /** @return ProcessIdentity|null */
    private function processIdentity(string $stat): ?array
    {
        $open = strpos($stat, '(');
        $close = strrpos($stat, ')');
        if ($open === false || $close === false || $close <= $open) {
            return null;
        }
        $pid = trim(substr($stat, 0, $open));
        if ($pid === '' || !ctype_digit($pid)) {
            return null;
        }
        $command = substr($stat, $open + 1, $close - $open - 1);
        if ($command === '' || preg_match('/[\x00-\x1F\x7F]/', $command) === 1) {
            return null;
        }
        $fields = preg_split('/\s+/', trim(substr($stat, $close + 1))) ?: [];
        $startTimeIndex = 19; // proc(5): field 22, relative to the text after field 2.
        if (!isset($fields[$startTimeIndex]) || !ctype_digit($fields[$startTimeIndex])) {
            return null;
        }

        return [
            'pid' => (int) $pid,
            'command' => $command,
            'start_ticks' => (int) $fields[$startTimeIndex],
        ];
    }

    /** @param ProcessIdentity|null $identity */
    private function identityMatches(?array $identity, int $pid, string $command): bool
    {
        return $identity !== null && $identity['pid'] === $pid && $identity['command'] === $command;
    }

    /**
     * @param ProcessIdentity|null $before
     * @param ProcessIdentity|null $after
     */
    private function sameProcessSnapshot(?array $before, ?array $after, int $pid, string $command): bool
    {
        return $before !== null && $after !== null
            && $before['pid'] === $pid && $after['pid'] === $pid
            && $before['command'] === $command && $after['command'] === $command
            && $before['start_ticks'] === $after['start_ticks'];
    }

    /** @return list<string> */
    private function safeExtensions(mixed $extensions): ?array
    {
        if (!is_array($extensions) || !array_is_list($extensions) || count($extensions) > 256) {
            return null;
        }
        $safe = [];
        foreach ($extensions as $extension) {
            if (!is_string($extension) || preg_match('/\A[a-zA-Z0-9_-]{1,64}\z/', $extension) !== 1) {
                return null;
            }
            $safe[] = strtolower($extension);
        }
        $safe = array_values(array_unique($safe));
        sort($safe, SORT_STRING);

        return $safe;
    }

    private static function safeToken(string $value, int $maxLength): ?string
    {
        $value = trim($value);
        if ($value === '' || strlen($value) > $maxLength || preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
            return null;
        }

        return $value;
    }

    private static function safePhpVersion(string $value): ?string
    {
        $value = trim($value);

        return preg_match('/\A[0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z][A-Za-z0-9.+-]{0,31})?\z/', $value) === 1
            ? $value
            : null;
    }

    private static function safeExecutablePath(string $path): ?string
    {
        $path = trim($path);
        if (str_ends_with($path, ' (deleted)')) {
            $path = substr($path, 0, -10);
        }
        if (strlen($path) > 512 || preg_match('~\A/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]+\z~', $path) !== 1) {
            return null;
        }
        foreach (explode('/', trim($path, '/')) as $segment) {
            if ($segment === '.' || $segment === '..') {
                return null;
            }
        }

        return $path;
    }

    private static function isPhpPackageName(string $name): bool
    {
        return preg_match('/\A(?:php(?:[0-9.]*(?:-[a-z0-9.+-]+)?)?|libapache2-mod-php(?:[0-9.]*)|mod_php(?:[0-9.]*)|php-main)\z/i', $name) === 1;
    }

    private function addFact(string $key, mixed $value, string $sourceId): void
    {
        $id = 'fact.' . str_replace([' ', '/'], ['-', '.'], $key);
        if (strlen($id) > 128 || strlen($key) > 128) {
            return;
        }
        $this->facts[] = ['fact_id' => $id, 'key' => $key, 'value' => $value, 'source_id' => $sourceId];
    }

    private function addSource(string $kind, string $locator, ?string $content): string
    {
        if (isset($this->sourceByLocator[$locator])) {
            return $this->sourceByLocator[$locator];
        }
        $sourceId = 'source.' . substr(hash('sha256', $locator), 0, 20);
        $digest = $content === null ? null : 'sha256:' . hash('sha256', $content);
        $this->sources[] = [
            'source_id' => $sourceId,
            'kind' => $kind,
            'locator' => substr($locator, 0, 256),
            'captured_at' => $this->observedAt,
            'captured_digest' => $digest,
            'current_digest' => $digest,
            'freshness' => $digest === null ? 'unknown' : 'fresh',
        ];
        $this->sourceByLocator[$locator] = $sourceId;

        return $sourceId;
    }

    private function sourceIdFor(string $locator): string
    {
        return $this->sourceByLocator[$locator] ?? $this->addSource('other', $locator, null);
    }

    private function readFile(string $absolutePath, int $maxBytes): ?string
    {
        $path = $this->path($absolutePath);
        $real = realpath($path);
        if ($real === false || !$this->withinRoot($real) || !is_file($real)) {
            return null;
        }
        $size = filesize($real);
        if (!is_int($size) || $size > $maxBytes) {
            return null;
        }
        $contents = @file_get_contents($real, false, null, 0, $maxBytes + 1);

        return is_string($contents) && strlen($contents) <= $maxBytes ? $contents : null;
    }

    private function isFile(string $absolutePath): bool
    {
        $real = realpath($this->path($absolutePath));

        return $real !== false && $this->withinRoot($real) && is_file($real);
    }

    private function path(string $absolutePath): string
    {
        if ($this->rootRealPath === DIRECTORY_SEPARATOR) {
            return $absolutePath;
        }

        return $this->rootRealPath . DIRECTORY_SEPARATOR . ltrim($absolutePath, DIRECTORY_SEPARATOR);
    }

    private function withinRoot(string $realPath): bool
    {
        if ($this->rootRealPath === DIRECTORY_SEPARATOR) {
            return str_starts_with($realPath, DIRECTORY_SEPARATOR);
        }

        return $realPath === $this->rootRealPath || str_starts_with($realPath, $this->rootRealPath . DIRECTORY_SEPARATOR);
    }
}
