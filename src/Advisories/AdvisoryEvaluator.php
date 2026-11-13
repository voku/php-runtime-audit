<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Advisories;

use InvalidArgumentException;
use voku\PhpRuntimeAudit\RuntimeInventory\FpmVersionName;
use voku\PhpRuntimeAudit\RuntimeInventory\RuntimeInventoryCollector;

/**
 * Evaluates vendor evidence conservatively; missing provenance never becomes a fix claim.
 *
 * @phpstan-import-type RuntimeInventory from RuntimeInventoryCollector
 * @phpstan-import-type AdvisoryDefinition from AdvisoryCatalog
 * @phpstan-import-type VendorRule from AdvisoryCatalog
 * @phpstan-import-type RuntimeFact from RuntimeInventoryCollector
 * @phpstan-import-type RuntimeConfigSetting from RuntimeInventoryCollector
 * @phpstan-type RuntimeTarget array{id: string, subject_id: string, kind: string, runtime_path: string|null, runtime_path_fact_id: string|null, parent_pid: int|null, process_start_ticks_since_boot: int|null, fpm_configuration_path: string|null, fpm_configuration_state: 'default'|'observed'|'pool'|'unavailable', fpm_pool_name: string|null, version: string|null, package: string|null, package_version: string|null, source_fact_id: string|null, package_fact_id: string|null, package_identity_fact_ids?: list<string>, deleted: bool|null, provenance_verified: bool, provenance_fact_id: string|null, worker_namespace_verified?: bool, apache_namespace_verified?: bool}
 * @phpstan-type AdvisorySource array{source_id: string, kind: 'vendor_advisory'|'other', locator: string, captured_at: string, captured_digest: string|null, current_digest: null, freshness: 'unknown'}
 * @phpstan-type AdvisoryFact array{fact_id: string, key: string, value: mixed, source_id: string}
 * @phpstan-type AdvisoryAssessment array{record_type: 'assessment', schema_version: '1.0', record_id: string, subject_id: string, assessed_at: string, verdict: string, patch_status: string, patch_evidence_ids: list<string>, compromise_evidence: array{status: 'unknown', evidence_ids: list<string>}, rationale: string}
 * @phpstan-type AdvisoryCoverage array{check_id: string, status: 'attempted'|'blocked', evidence_ids: list<string>, gap: string|null}
 * @phpstan-type AdvisoryEvaluation array{sources: list<AdvisorySource>, facts: list<AdvisoryFact>, assessments: list<AdvisoryAssessment>, coverage: list<AdvisoryCoverage>}
 */
final class AdvisoryEvaluator
{
    private const MAX_TARGETS = 128;

    /**
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-return AdvisoryEvaluation
     */
    public function evaluate(array $inventory, AdvisoryCatalog $catalog): array
    {
        $observedAt = $inventory['observed_at'];
        /** @var list<AdvisoryDefinition> $advisories */
        $advisories = $catalog->advisories;
        $targetSelection = $this->runtimeTargets($inventory, $advisories);
        $targets = $targetSelection['targets'];
        $observedTargetCount = $targetSelection['observed_count'];
        $omittedTargetCount = max(0, $observedTargetCount - self::MAX_TARGETS);
        /** @var list<RuntimeTarget> $targets */
        $targets = $targets;
        if ($targets === []) {
            $targets[] = ['id' => 'web-runtime-unknown', 'subject_id' => 'local-host', 'kind' => 'unknown', 'runtime_path' => null, 'runtime_path_fact_id' => null, 'parent_pid' => null, 'process_start_ticks_since_boot' => null, 'fpm_configuration_path' => null, 'fpm_configuration_state' => 'unavailable', 'fpm_pool_name' => null, 'version' => null, 'package' => null, 'package_version' => null, 'source_fact_id' => null, 'package_fact_id' => null, 'deleted' => false, 'provenance_verified' => false, 'provenance_fact_id' => null];
        }

        /** @var list<AdvisorySource> $sources */
        $sources = [[
            'source_id' => 'source.advisory-catalog',
            'kind' => 'other',
            'locator' => 'php-runtime-audit:advisory-catalog:' . $catalog->digest,
            'captured_at' => $catalog->loadedAt,
            'captured_digest' => $catalog->digest,
            'current_digest' => null,
            'freshness' => 'unknown',
        ]];
        /** @var list<AdvisoryFact> $facts */
        $facts = [];
        $catalogFactId = $this->addFact($facts, 'advisory.catalog', [
            'digest' => $catalog->digest,
            'as_of' => $catalog->asOf,
            'scope' => 'bundled rules, not captured remote advisory bodies',
        ], 'source.advisory-catalog');
        /** @var list<AdvisoryCoverage> $coverage */
        $coverage = [];
        if ($omittedTargetCount > 0) {
            $targetSourceId = 'source.advisory-target-selection';
            $sources[] = [
                'source_id' => $targetSourceId,
                'kind' => 'other',
                'locator' => 'php-runtime-audit:advisory-target-selection',
                'captured_at' => $catalog->loadedAt,
                'captured_digest' => null,
                'current_digest' => null,
                'freshness' => 'unknown',
            ];
            $targetSelectionFactId = $this->addFact($facts, 'advisory.assessment_targets.truncated', [
                'limit' => self::MAX_TARGETS,
                'observed' => $observedTargetCount,
                'included' => count($targets),
                'omitted' => $omittedTargetCount,
            ], $targetSourceId);
            $coverage[] = [
                'check_id' => 'advisory.assessment_targets',
                'status' => 'blocked',
                'evidence_ids' => [$targetSelectionFactId],
                'gap' => sprintf(
                    'The assessment target limit omitted %d runtime or package subject; omitted subjects have no advisory assessment.',
                    $omittedTargetCount,
                ),
            ];
        }
        /** @var list<AdvisoryAssessment> $assessments */
        $assessments = [];
        $sourceIds = [];
        foreach ($advisories as $advisory) {
            $mainSourceId = $this->addAdvisorySource($sources, $sourceIds, $advisory['source_url'], $catalog->loadedAt);
            $asOfFact = $this->addFact($facts, 'advisory.' . $advisory['cve'] . '.as_of', $catalog->asOf, $mainSourceId);
            $fixedUpstreamFact = $this->addFact(
                $facts,
                'advisory.' . $advisory['cve'] . '.fixed_upstream',
                $advisory['fixed_upstream'],
                $mainSourceId,
            );
            foreach ($advisory['mitigations'] as $mitigationIndex => $mitigation) {
                $mitigationSourceId = $this->addAdvisorySource(
                    $sources,
                    $sourceIds,
                    $mitigation['source_url'],
                    $catalog->loadedAt,
                );
                $this->addFact(
                    $facts,
                    'advisory.' . $advisory['cve'] . '.mitigation.' . ($mitigationIndex + 1),
                    [
                        'setting' => $mitigation['setting'],
                        'value' => $mitigation['value'],
                        'effect' => $mitigation['effect'],
                        'as_of' => $catalog->asOf,
                        'revision' => $advisory['revision'],
                        'source_url' => $mitigation['source_url'],
                    ],
                    $mitigationSourceId,
                );
            }
            foreach ($targets as $target) {
                $targetId = $target['subject_id'];
                $rule = $this->matchingVendorRule($advisory, $inventory, $target);
                $sourceId = $mainSourceId;
                if ($rule !== null) {
                    $sourceId = $this->addAdvisorySource($sources, $sourceIds, $rule['source_url'], $catalog->loadedAt);
                }
                $applicability = $this->applicability($advisory, $inventory, $target, $rule);
                $applicabilityFact = $this->addFact(
                    $facts,
                    'advisory.' . $advisory['cve'] . '.' . $targetId . '.applicability',
                    $applicability,
                    $sourceId,
                );
                $vendorEvidenceIds = array_values(array_filter([
                    $this->factId($inventory['facts'], 'os.id'),
                    $this->factId($inventory['facts'], 'os.version_id'),
                    $this->factId($inventory['facts'], 'os.version_codename'),
                    $this->factId($inventory['facts'], 'packages.manager'),
                    $this->factId($inventory['facts'], 'packages.state'),
                ], static fn(?string $id): bool => $id !== null));
                $basis = $this->assess($advisory, $inventory, $target, $rule);
                $configurationFactIds = $this->configurationFactIdsForTarget($advisory['cve'], $inventory, $target, $facts);
                $basisFact = $this->addFact(
                    $facts,
                    'advisory.' . $advisory['cve'] . '.' . $targetId . '.assessment_basis',
                    [
                        'as_of' => $catalog->asOf,
                        'revision' => $rule['revision'] ?? $advisory['revision'],
                        'source_url' => $rule['source_url'] ?? $advisory['source_url'],
                        'runtime_fact_id' => $target['source_fact_id'],
                        'runtime_path_fact_id' => $target['runtime_path_fact_id'],
                        'package_fact_id' => $target['package_fact_id'],
                        'worker_package_provenance_fact_id' => $target['provenance_fact_id'],
                        'configuration_fact_ids' => $configurationFactIds,
                        'vendor_fact_ids' => $vendorEvidenceIds,
                        'vendor' => $inventory['distribution'],
                        'release' => $rule['release'] ?? $this->releaseName($inventory),
                        'package_manager' => $inventory['package_manager'],
                        'upstream_fixed_fact_id' => $fixedUpstreamFact,
                        'reason' => $basis['reason'],
                    ],
                    $sourceId,
                );
                $evidenceIds = [];
                foreach ([
                    $target['source_fact_id'],
                    $target['runtime_path_fact_id'],
                    $target['package_fact_id'],
                    ...($target['package_identity_fact_ids'] ?? []),
                    $target['provenance_fact_id'],
                    ...$vendorEvidenceIds,
                    $catalogFactId,
                    $asOfFact,
                    $fixedUpstreamFact,
                    $applicabilityFact,
                    $basisFact,
                ] as $evidenceId) {
                    if ($evidenceId !== null) {
                        $evidenceIds[] = $evidenceId;
                    }
                }
                $evidenceIds = array_values(array_unique($evidenceIds));
                $assessment = [
                    'record_type' => 'assessment',
                    'schema_version' => '1.0',
                    'record_id' => 'assessment:' . $advisory['cve'] . ':' . $target['subject_id'],
                    'subject_id' => $target['subject_id'],
                    'assessed_at' => $observedAt,
                    'verdict' => $basis['verdict'],
                    'patch_status' => $basis['patch_status'],
                    'patch_evidence_ids' => in_array($basis['patch_status'], ['verified_fixed', 'potentially_affected'], true) ? $evidenceIds : [],
                    'compromise_evidence' => ['status' => 'unknown', 'evidence_ids' => []],
                    'rationale' => $this->rationale($advisory, $catalog->asOf, $target, $basis, $rule),
                ];
                $assessments[] = $assessment;
            }
        }

        return ['sources' => $sources, 'facts' => $facts, 'assessments' => $assessments, 'coverage' => $coverage];
    }

    /**
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-param list<AdvisoryDefinition> $advisories
     * @phpstan-return array{targets: list<RuntimeTarget>, observed_count: int}
     */
    private function runtimeTargets(array $inventory, array $advisories): array
    {
        $packages = $inventory['packages'];
        $facts = $inventory['facts'];
        $targets = [];
        $observedTargetCount = 0;
        foreach ($inventory['workers'] as $index => $worker) {
            $workerIndex = $index + 1;
            if ($worker['kind'] === 'fpm') {
                ++$observedTargetCount;
                if ($observedTargetCount > self::MAX_TARGETS) {
                    continue;
                }

                $executablePath = $worker['executable_path'];
                $runtimePathFactId = $this->factId($facts, 'worker.' . $workerIndex . '.executable_path');
                $version = $worker['version'];
                $sourceFactId = $this->factId($facts, 'worker.' . $workerIndex . '.version');
                if ($worker['fpm_configuration_state'] === 'pool'
                    && ($executablePath === null || $version === null)) {
                    $parentRuntime = $this->fpmParentRuntime($worker, $inventory);
                    if ($parentRuntime !== null) {
                        $parentPath = $parentRuntime['worker']['executable_path'];
                        $parentVersion = $parentRuntime['worker']['version'];
                        if (is_string($parentPath)
                            && ($executablePath === null || $executablePath === $parentPath)
                            && ($version === null || $version === $parentVersion)) {
                            $executablePath = $parentPath;
                            $runtimePathFactId = $this->factId(
                                $facts,
                                'worker.' . ($parentRuntime['index'] + 1) . '.executable_path',
                            );
                            if (is_string($parentVersion)) {
                                $version = $parentVersion;
                            }
                            $sourceFactId = $this->factId(
                                $facts,
                                'worker.' . ($parentRuntime['index'] + 1) . '.version',
                            );
                        }
                    }
                }
                $packageName = $worker['worker_namespace_verified']
                    ? $this->fpmPackageName($executablePath, $inventory['distribution'] ?? '')
                    : null;
                $package = $this->findPackage($packages, $packageName);
                if ($package === null && is_string($executablePath) && str_starts_with($executablePath, '/usr/local/')) {
                    $packageName = null;
                }
                $targets[] = [
                    'provenance_verified' => $worker['package_provenance']['verified']
                        && $worker['package_provenance']['package_name'] === $packageName
                        && $worker['package_provenance']['package_version'] === ($package['version'] ?? null)
                        && $worker['package_provenance']['executable_path'] === $executablePath,
                    'provenance_fact_id' => $this->factId($facts, 'worker.' . $workerIndex . '.package_provenance'),
                    'id' => 'worker-' . $workerIndex,
                    'subject_id' => $worker['id'],
                    'kind' => 'fpm',
                    'runtime_path' => $executablePath,
                    'runtime_path_fact_id' => $runtimePathFactId,
                    'parent_pid' => $worker['parent_pid'],
                    'process_start_ticks_since_boot' => $worker['process_start_ticks_since_boot'],
                    'fpm_configuration_path' => $worker['fpm_configuration_path'],
                    'fpm_configuration_state' => $worker['fpm_configuration_state'],
                    'fpm_pool_name' => $worker['fpm_pool_name'],
                    'version' => $version,
                    'package' => $packageName,
                    'package_version' => $package['version'] ?? null,
                    'source_fact_id' => $sourceFactId,
                    'package_fact_id' => $package['fact_id'] ?? null,
                    'deleted' => $worker['executable_deleted'],
                    'worker_namespace_verified' => $worker['worker_namespace_verified'],
                ];
                continue;
            }
            if ($worker['apache_php_modules'] === null) {
                continue;
            }
            foreach ($worker['apache_php_modules'] as $moduleIndex => $modulePath) {
                ++$observedTargetCount;
                if ($observedTargetCount > self::MAX_TARGETS) {
                    continue;
                }

                $namespaceVerified = $worker['apache_namespace_verified'] ?? false;
                // The loaded module's filename does not reliably encode its version (modern
                // builds ship an unversioned libphp.so); dpkg-confirmed provenance of the exact
                // loaded path is authoritative when available, with the filename guess as a
                // fallback only when the worker's mount namespace and process root are verified.
                $moduleProvenance = $namespaceVerified
                    && $worker['package_provenance']['verified']
                    && $worker['package_provenance']['executable_path'] === $modulePath;
                $moduleName = basename($modulePath);
                $packageName = $moduleProvenance
                    ? $worker['package_provenance']['package_name']
                    : ($namespaceVerified && preg_match('/\Alibphp([0-9]+\.[0-9]+)\.so\z/', $moduleName, $matches) === 1
                        ? 'libapache2-mod-php' . $matches[1]
                        : null);
                $package = $this->findPackage($packages, $packageName);
                $targets[] = [
                    'provenance_verified' => $moduleProvenance
                        && $package !== null
                        && $package['version'] === $worker['package_provenance']['package_version'],
                    'provenance_fact_id' => $this->factId($facts, 'worker.' . $workerIndex . '.package_provenance'),
                    'id' => 'apache-' . $worker['pid'] . '-' . ($worker['process_start_ticks_since_boot'] ?? 'unknown') . '-' . ($moduleIndex + 1),
                    'subject_id' => 'apache-' . $worker['pid'] . '-' . ($worker['process_start_ticks_since_boot'] ?? 'unknown') . '-' . ($moduleIndex + 1),
                    'kind' => 'apache-mod-php',
                    'runtime_path' => $modulePath,
                    'runtime_path_fact_id' => $this->factId($facts, 'worker.' . $workerIndex . '.apache_php_modules'),
                    'parent_pid' => $worker['parent_pid'],
                    'process_start_ticks_since_boot' => $worker['process_start_ticks_since_boot'],
                    'fpm_configuration_path' => null,
                    'fpm_configuration_state' => 'unavailable',
                    'fpm_pool_name' => null,
                    // Package inventory is installed-state evidence. It cannot establish which
                    // mod_php binary is still mapped into an already-running Apache process.
                    'version' => null,
                    'package' => $packageName,
                    'package_version' => $package['version'] ?? null,
                    'source_fact_id' => $this->factId($facts, 'worker.' . $workerIndex . '.apache_php_modules'),
                    'package_fact_id' => $package['fact_id'] ?? null,
                    'deleted' => $worker['apache_php_module_deleted_paths'] === null
                        ? null
                        : in_array($modulePath, $worker['apache_php_module_deleted_paths'], true),
                    'apache_namespace_verified' => $worker['apache_namespace_verified'] ?? false,
                    'worker_namespace_verified' => $worker['worker_namespace_verified'],
                ];
            }
        }

        /** @var list<array{id: string, binary_path: string, version: string|null}> $fpmExecutables */
        $fpmExecutables = $inventory['fpm_executables'] ?? [];
        foreach ($fpmExecutables as $index => $executable) {
            ++$observedTargetCount;
            if ($observedTargetCount > self::MAX_TARGETS) {
                continue;
            }

            $packageName = $this->fpmPackageName($executable['binary_path'], $inventory['distribution'] ?? '');
            $package = $this->findPackage($packages, $packageName);
            $targets[] = [
                'id' => $executable['id'],
                'subject_id' => $executable['id'],
                'kind' => 'fpm-executable',
                'runtime_path' => $executable['binary_path'],
                'runtime_path_fact_id' => $this->factId($facts, 'runtime.fpm_executable.' . ($index + 1) . '.binary_path'),
                'parent_pid' => null,
                'process_start_ticks_since_boot' => null,
                'fpm_configuration_path' => null,
                'fpm_configuration_state' => 'unavailable',
                'fpm_pool_name' => null,
                'version' => $executable['version'],
                'package' => $packageName,
                'package_version' => $package['version'] ?? null,
                'source_fact_id' => $this->factId($facts, 'runtime.fpm_executable.' . ($index + 1) . '.version'),
                'package_fact_id' => $package['fact_id'] ?? null,
                'deleted' => false,
                'provenance_verified' => false,
                'provenance_fact_id' => null,
            ];
        }

        $runtimeIndex = 0;
        foreach ($inventory['runtimes'] as $runtime) {
            ++$runtimeIndex;
            if (!is_string($runtime['id'] ?? null)
                || !is_string($runtime['binary_path'] ?? null)
                || !is_string($runtime['version'] ?? null)) {
                continue;
            }
            ++$observedTargetCount;
            if ($observedTargetCount > self::MAX_TARGETS) {
                continue;
            }

            $packageName = $this->cliPackageName($runtime['binary_path'], $inventory['distribution'] ?? '');
            $package = $this->findPackage($packages, $packageName);
            $targets[] = [
                'id' => $runtime['id'], 'subject_id' => $runtime['id'], 'kind' => 'cli',
                'runtime_path' => $runtime['binary_path'],
                'runtime_path_fact_id' => $this->factId($facts, 'runtime.cli.' . $runtimeIndex . '.binary_path'),
                'parent_pid' => null,
                'process_start_ticks_since_boot' => null,
                'fpm_configuration_path' => null,
                'fpm_configuration_state' => 'unavailable',
                'fpm_pool_name' => null,
                'version' => $runtime['version'], 'package' => $packageName,
                'package_version' => $package['version'] ?? null,
                'source_fact_id' => $this->factId($facts, 'runtime.cli.' . $runtimeIndex . '.version'),
                'package_fact_id' => $package['fact_id'] ?? null, 'deleted' => false,
                'provenance_verified' => false, 'provenance_fact_id' => null,
            ];
        }

        foreach ($packages as $index => $package) {
            if (!$this->isRuntimePackageName($package['name'], $advisories)) {
                continue;
            }
            ++$observedTargetCount;
            if ($observedTargetCount > self::MAX_TARGETS) {
                continue;
            }

            $architecture = $package['architecture'] ?? null;
            $packageIdentity = $package['name'] . "\0" . $package['version']
                . (is_string($architecture) ? "\0" . $architecture : '');
            $packageId = 'package-' . substr(hash('sha256', $packageIdentity), 0, 20);
            $packageFactId = $this->factId($facts, 'package.' . $index . '.version');
            $packageIdentityFactIds = array_values(array_filter([
                $this->factId($facts, 'package.' . $index . '.name'),
                $this->factId($facts, 'package.' . $index . '.architecture'),
            ], static fn(?string $factId): bool => $factId !== null));
            $targets[] = [
                'id' => $packageId, 'subject_id' => $packageId, 'kind' => 'package',
                'runtime_path' => null,
                'runtime_path_fact_id' => null,
                'parent_pid' => null,
                'process_start_ticks_since_boot' => null,
                'fpm_configuration_path' => null,
                'fpm_configuration_state' => 'unavailable',
                'fpm_pool_name' => null,
                'version' => $this->upstreamVersion($package['version']), 'package' => $package['name'],
                'package_version' => $package['version'], 'source_fact_id' => $packageFactId,
                'package_fact_id' => $packageFactId,
                'package_identity_fact_ids' => $packageIdentityFactIds,
                'deleted' => false,
                'provenance_verified' => $inventory['package_inventory_state'] === 'attempted' && $packageFactId !== null,
                'provenance_fact_id' => $packageFactId,
            ];
        }

        return ['targets' => $targets, 'observed_count' => $observedTargetCount];
    }

    /** @param list<array{name: string, version: string, architecture?: string|null}> $packages
     * @return array{version: string, fact_id: string}|null
     */
    private function findPackage(array $packages, ?string $name): ?array
    {
        if ($name === null) {
            return null;
        }
        $match = null;
        foreach ($packages as $index => $package) {
            if ($package['name'] === $name) {
                if ($match !== null) {
                    return null;
                }
                $match = ['version' => $package['version'], 'fact_id' => 'fact.package.' . $index . '.version'];
            }
        }

        return $match;
    }

    private function cliPackageName(string $path, string $distribution): ?string
    {
        if (str_starts_with($path, '/usr/local/')) {
            return null;
        }
        if (preg_match('~\A/opt/remi/php([0-9]{2,3})/root/usr/bin/php\z~', $path, $matches) === 1) {
            return 'php' . $matches[1] . '-php-cli';
        }
        if ($distribution === 'alpine' && preg_match('/\Aphp(8[2-5])\z/', basename($path), $matches) === 1) {
            return 'php' . $matches[1];
        }
        if (preg_match('/\Aphp(5\.[0-9]+|7\.[0-9]+|8\.[0-9]+)\z/', basename($path), $matches) === 1) {
            return 'php' . $matches[1] . '-cli';
        }
        if (preg_match('/\Aphp([0-9]{2,3})\z/', basename($path), $matches) === 1) {
            return 'php' . $matches[1] . '-cli';
        }
        return basename($path) === 'php' ? 'php-cli' : null;
    }

    /** @phpstan-param list<AdvisoryDefinition> $advisories */
    private function isRuntimePackageName(string $name, array $advisories): bool
    {
        if (preg_match('/\Aphp[0-9]{2,3}-php-(?:cli|fpm|cgi)\z/', $name) === 1
            || preg_match('/\Aphp(?:[0-9]+(?:\.[0-9]+)?|[0-9]{2,3})?-(?:cli|fpm|cgi)\z/', $name) === 1
            || preg_match('/\Alibapache2-mod-php(?:[0-9]+(?:\.[0-9]+)?)?\z/', $name) === 1
            || preg_match('/\Aphp[0-9]{2,3}\z/', $name) === 1) {
            return true;
        }

        foreach ($advisories as $advisory) {
            foreach ($advisory['vendor_rules'] as $rule) {
                if (in_array($name, $rule['package_names'], true)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Select config observations only when the observed root matches this runtime's known layout.
     *
     * @phpstan-param RuntimeConfigSetting $setting
     * @phpstan-param RuntimeTarget $target
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-return RuntimeConfigSetting
     */
    private function configurationForTarget(array $setting, array $target, array $inventory): array
    {
        if ($setting['state'] === 'unknown' && $setting['observations'] === []) {
            return ['value' => null, 'state' => 'unknown', 'files' => [], 'observations' => []];
        }

        $expectedRoot = $this->configurationRootForTarget($target, $inventory);
        if ($expectedRoot === null
            || ($target['kind'] === 'fpm' && $target['fpm_configuration_state'] === 'pool' && $target['fpm_pool_name'] === null)
            || ($target['kind'] === 'fpm' && $this->fpmEntrypointSymlinked($expectedRoot, $inventory))) {
            return ['value' => null, 'state' => 'unknown', 'files' => [], 'observations' => []];
        }
        $observations = array_values(array_filter(
            $setting['observations'],
            static fn(array $observation): bool => $observation['configuration_root'] === $expectedRoot
                && ($target['kind'] !== 'fpm'
                    || $observation['context'] === 'global'
                    || ($target['fpm_pool_name'] !== null
                        && $observation['context'] === 'pool:' . $target['fpm_pool_name'])),
        ));
        $values = array_values(array_unique(array_column($observations, 'value')));
        $state = count($values) > 1 ? 'conflict' : ($values === [] ? 'unknown' : 'observed');
        return [
            'value' => $state === 'observed' ? $values[0] : null,
            'state' => $state,
            'files' => array_values(array_unique(array_column($observations, 'file'))),
            'observations' => $observations,
        ];
    }

    /**
     * @phpstan-param RuntimeInventory $inventory
     */
    private function fpmEntrypointSymlinked(string $configurationRoot, array $inventory): bool
    {
        foreach ($inventory['facts'] as $fact) {
            if ($fact['key'] === 'configuration.fpm_entrypoint_symlink_roots'
                && is_array($fact['value'])
                && in_array($configurationRoot, $fact['value'], true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Bind FPM settings to the worker's explicit config path, or to its captured parent when the
     * process title has discarded argv. A custom or unavailable config never falls back to the
     * executable's default config tree.
     *
     * @phpstan-param RuntimeTarget $target
     * @phpstan-param RuntimeInventory $inventory
     */
    private function configurationRootForTarget(array $target, array $inventory): ?string
    {
        if ($target['kind'] === 'fpm') {
            if (!($target['worker_namespace_verified'] ?? false)) {
                return null;
            }
            $expectedRoot = $this->defaultFpmConfigurationRoot($target, $inventory);
            if ($expectedRoot === null) {
                return null;
            }

            $configurationPath = $target['fpm_configuration_path'];
            $configurationState = $target['fpm_configuration_state'];
            if ($configurationState === 'pool') {
                $parent = $this->fpmConfigurationParent($target, $inventory);
                if ($parent === null) {
                    return null;
                }
                if (!$parent['worker_namespace_verified']) {
                    return null;
                }
                $configurationPath = $parent['fpm_configuration_path'];
                $configurationState = $parent['fpm_configuration_state'];
            }

            if ($configurationState === 'default') {
                return $expectedRoot;
            }

            return $configurationState === 'observed' && $configurationPath === $expectedRoot . '/php-fpm.conf'
                ? $expectedRoot
                : null;
        }

        if ($target['kind'] === 'apache-mod-php'
            && ($target['apache_namespace_verified'] ?? false)
            && in_array($inventory['distribution'] ?? null, ['debian', 'ubuntu'], true)
            && $target['runtime_path'] !== null) {
            if (preg_match('~\A/usr/lib/apache2/modules/libphp([0-9]+\.[0-9]+)\.so\z~', $target['runtime_path'], $matches) === 1) {
                return '/etc/php/' . $matches[1] . '/apache2';
            }

            if ($target['runtime_path'] === '/usr/lib/apache2/modules/libphp.so'
                && $target['provenance_verified']
                && is_string($target['package'])
                && preg_match('/\Alibapache2-mod-php([0-9]+\.[0-9]+)\z/', $target['package'], $matches) === 1
                && $this->versionBranch($target['package_version']) === $matches[1]) {
                return '/etc/php/' . $matches[1] . '/apache2';
            }
        }

        return null;
    }

    /**
     * Return the known compile-time/default config root for supported FPM executable layouts.
     *
     * @phpstan-param RuntimeTarget $target
     * @phpstan-param RuntimeInventory $inventory
     */
    private function defaultFpmConfigurationRoot(array $target, array $inventory): ?string
    {
        $runtimePath = $target['runtime_path'];
        if ($runtimePath === '/usr/local/sbin/php-fpm') {
            return '/usr/local/etc';
        }
        if (in_array($inventory['distribution'] ?? null, ['centos', 'fedora', 'almalinux', 'ol', 'rocky', 'rhel'], true)
            && $runtimePath === '/usr/sbin/php-fpm') {
            return '/etc';
        }
        $branch = $this->versionBranch($target['version']);
        if ($runtimePath === null || $branch === null) {
            return null;
        }
        if (preg_match('~\A/opt/remi/php([0-9]{2,3})/root/usr/sbin/php-fpm\z~', $runtimePath, $matches) === 1) {
            $pathBranch = FpmVersionName::fromCompactBranch($matches[1]);
            return $branch === $pathBranch ? '/etc/opt/remi/php' . $matches[1] : null;
        }
        if (preg_match('~\A/usr/sbin/php-fpm([0-9]+)\.([0-9]+)\z~', $runtimePath, $matches) === 1) {
            $pathBranch = $matches[1] . '.' . $matches[2];
            return $branch === $pathBranch ? '/etc/php/' . $pathBranch . '/fpm' : null;
        }
        if (($inventory['distribution'] ?? null) === 'alpine'
            && preg_match('~\A/usr/sbin/php-fpm([0-9]{2,3})\z~', $runtimePath, $matches) === 1) {
            $pathBranch = FpmVersionName::fromCompactBranch($matches[1]);
            return $branch === $pathBranch ? '/etc/php' . $matches[1] : null;
        }
        return null;
    }

    /**
     * A pool process can hide argv and deny access to its executable link. Bind it to a
     * captured FPM parent only when the process identity and start-time ordering agree.
     *
     * @phpstan-param RuntimeInventory['workers'][int] $worker
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-return array{worker: RuntimeInventory['workers'][int], index: int}|null
     */
    private function fpmParentRuntime(array $worker, array $inventory): ?array
    {
        if ($worker['parent_pid'] === null
            || $worker['process_start_ticks_since_boot'] === null
            || !$worker['worker_namespace_verified']
            || $worker['fpm_configuration_state'] !== 'pool'
            || $worker['fpm_pool_name'] === null) {
            return null;
        }

        foreach ($inventory['workers'] as $index => $candidate) {
            if ($candidate['kind'] !== 'fpm'
                || $candidate['pid'] !== $worker['parent_pid']
                || $candidate['process_start_ticks_since_boot'] === null
                || $candidate['process_start_ticks_since_boot'] >= $worker['process_start_ticks_since_boot']
                || !$candidate['worker_namespace_verified']
                || $candidate['executable_path'] === null
                || $candidate['executable_deleted'] !== false
                || $candidate['fpm_pool_name'] !== null
                || !in_array($candidate['fpm_configuration_state'], ['default', 'observed'], true)) {
                continue;
            }
            $workerVersion = FpmVersionName::fromProcessName(basename($worker['process_name'] ?? ''));
            $parentVersion = FpmVersionName::fromProcessName(basename($candidate['executable_path']));
            if ($workerVersion !== null && $workerVersion !== $parentVersion) {
                continue;
            }

            return ['worker' => $candidate, 'index' => $index];
        }

        return null;
    }

    /**
     * @phpstan-param RuntimeTarget $target
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-return RuntimeInventory['workers'][int]|null
     */
    private function fpmConfigurationParent(array $target, array $inventory): ?array
    {
        if ($target['parent_pid'] === null
            || $target['runtime_path'] === null
            || $target['process_start_ticks_since_boot'] === null) {
            return null;
        }
        foreach ($inventory['workers'] as $worker) {
            if ($worker['kind'] === 'fpm'
                && $worker['pid'] === $target['parent_pid']
                && $worker['process_start_ticks_since_boot'] !== null
                && $worker['process_start_ticks_since_boot'] < $target['process_start_ticks_since_boot']
                && $worker['executable_path'] === $target['runtime_path']
                && $worker['executable_deleted'] === false
                && $worker['fpm_pool_name'] === null
                && in_array($worker['fpm_configuration_state'], ['default', 'observed'], true)
                && $worker['version'] === $target['version']) {
                return $worker;
            }
        }

        return null;
    }

    /**
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-param RuntimeTarget $target
     * @phpstan-param list<AdvisoryFact> $facts
     * @return list<string>
     */
    private function configurationFactIdsForTarget(string $cve, array $inventory, array $target, array &$facts): array
    {
        if ($cve !== 'CVE-2026-115560') {
            return [];
        }
        $sapi = match ($target['kind']) {
            'fpm' => 'fpm',
            'apache-mod-php' => 'apache2',
            default => null,
        };
        if ($sapi === null) {
            return [];
        }

        $factIds = [];
        foreach (['session.upload_progress.enabled', 'session.serialize_handler'] as $settingName) {
            $setting = $this->configurationForTarget(
                $inventory['configuration_by_sapi'][$sapi][$settingName],
                $target,
                $inventory,
            );
            if ($setting['observations'] === []) {
                continue;
            }
            $sourceId = $this->factSourceId($inventory['facts'], 'configuration.' . $sapi . '.' . $settingName);
            if ($sourceId !== null) {
                $targetKey = substr(hash('sha256', $target['id']), 0, 16);
                $factIds[] = $this->addFact(
                    $facts,
                    'configuration.target.' . $targetKey . '.' . $sapi . '.' . $settingName,
                    $setting,
                    $sourceId,
                );
            }
        }

        return array_values(array_unique($factIds));
    }

    /**
     * @phpstan-param RuntimeConfigSetting $firstSetting
     * @phpstan-param list<string> $firstExpected
     * @phpstan-param RuntimeConfigSetting $secondSetting
     * @phpstan-param list<string> $secondExpected
     */
    private function hasCooccurringConfigurationObservations(
        array $firstSetting,
        array $firstExpected,
        array $secondSetting,
        array $secondExpected,
    ): bool {
        foreach ($firstSetting['observations'] as $firstObservation) {
            if (!in_array(strtolower($firstObservation['value']), $firstExpected, true)) {
                continue;
            }
            foreach ($secondSetting['observations'] as $secondObservation) {
                if (!in_array(strtolower($secondObservation['value']), $secondExpected, true)) {
                    continue;
                }
                if ($firstObservation['configuration_root'] === null
                    || $secondObservation['configuration_root'] === null
                    || $firstObservation['configuration_root'] !== $secondObservation['configuration_root']) {
                    continue;
                }
                if ($firstObservation['context'] === 'global'
                    || $secondObservation['context'] === 'global'
                    || $firstObservation['context'] === $secondObservation['context']) {
                    return true;
                }
            }
        }

        return false;
    }

    private function fpmPackageName(mixed $path, string $distribution): ?string
    {
        if (!is_string($path) || str_starts_with($path, '/usr/local/')) {
            return null;
        }
        if (preg_match('~\A/opt/remi/php([0-9]{2,3})/root/usr/sbin/php-fpm\z~', $path, $matches) === 1) {
            return 'php' . $matches[1] . '-php-fpm';
        }
        $basename = basename($path);
        if ($distribution === 'alpine' && preg_match('/\Aphp-fpm([0-9]{2,3})\z/', $basename, $matches) === 1) {
            return dirname($path) === '/usr/sbin' ? 'php' . $matches[1] . '-fpm' : null;
        }
        if (preg_match('/\Aphp-fpm([0-9]+\.[0-9]+)\z/', $basename, $matches) === 1) {
            return dirname($path) === '/usr/sbin' ? 'php' . $matches[1] . '-fpm' : null;
        }
        if (preg_match('/\Aphp-fpm([0-9]{2,3})\z/', $basename, $matches) === 1) {
            return dirname($path) === '/usr/sbin' ? 'php' . $matches[1] . '-fpm' : null;
        }

        if ($basename === 'php-fpm' && dirname($path) === '/usr/sbin') {
            return 'php-fpm';
        }
        return null;
    }

    /**
     * @phpstan-param AdvisoryDefinition $advisory
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-param RuntimeTarget $target
     * @phpstan-return VendorRule|null
     */
    private function matchingVendorRule(array $advisory, array $inventory, array $target): ?array
    {
        $vendor = $inventory['distribution'] ?? '';
        $expectedPackageManager = match ($vendor) {
            'debian', 'ubuntu' => 'dpkg',
            'rhel' => 'rpm',
            'alpine' => 'apk',
            default => null,
        };
        if ($expectedPackageManager === null
            || $inventory['package_manager'] !== $expectedPackageManager
            || $inventory['package_inventory_state'] !== 'attempted') {
            return null;
        }
        $releaseName = $this->releaseName($inventory);
        foreach ($advisory['vendor_rules'] as $rule) {
            if ($rule['vendor'] !== $vendor
                || $rule['release'] !== $releaseName
                || $target['package'] === null
                || !in_array($target['package'], $rule['package_names'], true)) {
                continue;
            }
            $actualBranch = $this->versionBranch($target['package_version']);
            $fixedBranch = $this->versionBranch($rule['fixed_version']);
            if ($actualBranch !== null && $actualBranch === $fixedBranch) {
                return $rule;
            }
        }

        return null;
    }

    /** @phpstan-param RuntimeInventory $inventory */
    private function releaseName(array $inventory): string
    {
        $distribution = $inventory['distribution'] ?? null;
        if ($distribution === 'alpine' && is_string($inventory['distribution_version'] ?? null)
            && preg_match('/\A([0-9]+\.[0-9]+)/', $inventory['distribution_version'], $matches) === 1) {
            return $matches[1];
        }
        $releaseMap = match ($distribution) {
            'debian' => ['bookworm' => '12', 'trixie' => '13'],
            'ubuntu' => ['noble' => '24.04', 'resolute' => '26.04', 'stonking' => '26.10'],
            default => [],
        };
        $codename = $inventory['distribution_codename'] ?? null;
        $version = $inventory['distribution_version'] ?? null;
        if (is_string($codename) && is_string($version) && ($releaseMap[$codename] ?? null) === $version) {
            return $codename;
        }
        if ($distribution === 'rhel' && is_string($version) && preg_match('/\A(10)(?:\.[0-9]+)?\z/', $version, $matches) === 1) {
            return $matches[1];
        }

        return '';
    }

    /**
     * @phpstan-param AdvisoryDefinition $advisory
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-param RuntimeTarget $target
     * @phpstan-param VendorRule|null $rule
     * @phpstan-return array{verdict: string, patch_status: string, reason: string}
     */
    private function assess(array $advisory, array $inventory, array $target, ?array $rule): array
    {
        if ($advisory['cve'] === 'CVE-2026-115560') {
            $configurationSapi = match ($target['kind']) {
                'fpm' => 'fpm',
                'apache-mod-php' => 'apache2',
                default => null,
            };
            $knownWebRuntime = $configurationSapi !== null;
            $settingsObserved = false;
            $uploadSetting = ['value' => null, 'state' => 'unknown', 'files' => [], 'observations' => []];
            $serializeSetting = ['value' => null, 'state' => 'unknown', 'files' => [], 'observations' => []];
            if ($configurationSapi !== null) {
                $uploadSetting = $this->configurationForTarget(
                    $inventory['configuration_by_sapi'][$configurationSapi]['session.upload_progress.enabled'],
                    $target,
                    $inventory,
                );
                $serializeSetting = $this->configurationForTarget(
                    $inventory['configuration_by_sapi'][$configurationSapi]['session.serialize_handler'],
                    $target,
                    $inventory,
                );
                $settingsObserved = $uploadSetting['state'] === 'observed'
                    && $serializeSetting['state'] === 'observed';
            }
            $riskConfiguration = $knownWebRuntime
                && $this->hasCooccurringConfigurationObservations(
                    $uploadSetting,
                    ['1', 'on', 'true', 'yes'],
                    $serializeSetting,
                    ['php_binary', 'php_serialize'],
                );
            if ($riskConfiguration) {
                $reason = 'One or more inspected web-SAPI configuration sources contain upload progress enabled and a serialization handler named in the advisory; precedence, per-pool applicability, application code, request path, and runtime handler changes remain unverified.';
            } elseif (!$knownWebRuntime) {
                $reason = 'No PHP web runtime was identified; configuration alone cannot establish that the described path is reachable.';
            } elseif (!$settingsObserved) {
                $reason = 'Relevant configuration is missing or conflicting; .user.ini or Apache per-directory overrides and application code changes are not observed, and no upstream fixed release is listed.';
            } else {
                $reason = 'Inspected configuration does not meet the described startup conditions, but .user.ini or Apache per-directory overrides and application code may change effective behavior; applicability remains unknown.';
            }

            return [
                'verdict' => $riskConfiguration ? 'needs_investigation' : 'unknown',
                'patch_status' => 'unknown',
                'reason' => $reason,
            ];
        }

        $version = $target['version'];
        if ($version === null || $target['deleted']) {
            return [
                'verdict' => 'unknown',
                'patch_status' => 'unknown',
                'reason' => $target['deleted']
                    ? 'The active worker references a deleted executable; the installed package version does not establish the running code version.'
                    : 'The active web runtime version is unknown; CLI facts are not substituted for a web worker version.',
            ];
        }

        $rule = $rule ?? null;
        if ($target['package'] !== null && $target['package_version'] === null) {
            return [
                'verdict' => 'unknown',
                'patch_status' => 'unknown',
                'reason' => 'The active runtime has a package identity but its installed package version is unavailable.',
            ];
        }
        $runtimeUpstream = $this->upstreamVersion($version);
        $packageUpstream = $this->upstreamVersion($target['package_version']);
        if ($target['package_version'] !== null
            && ($runtimeUpstream === null || $packageUpstream === null || $runtimeUpstream !== $packageUpstream)) {
            return [
                'verdict' => 'unknown',
                'patch_status' => 'unknown',
                'reason' => 'The running worker version and installed package version do not identify the same upstream release; package status cannot prove the loaded code version.',
            ];
        }
        if ($rule !== null && $target['package_version'] !== null) {
            $comparison = $this->compareVendorVersions($target['package_version'], $rule['fixed_version']);
            if ($comparison === null) {
                return [
                    'verdict' => 'unknown',
                    'patch_status' => 'unknown',
                    'reason' => 'The installed vendor package version does not exactly identify the sourced fixed build and cannot be compared safely.',
                ];
            }
            if ($comparison === 0 && (!$target['provenance_verified'] || $target['provenance_fact_id'] === null)) {
                $identityGap = match ($target['kind']) {
                    'package' => 'the package subject does not prove a running runtime maps to that package',
                    'cli' => 'the CLI executable has not been proven to come from that package',
                    'fpm-executable' => 'the FPM executable has not been proven to come from that package',
                    default => 'ownership, integrity and loaded worker identity have not been established',
                };
                return [
                    'verdict' => 'unknown',
                    'patch_status' => 'unknown',
                    'reason' => 'The installed package matches the sourced fixed build, but ' . $identityGap . '. Package inventory and matching upstream versions alone cannot prove a running fix.',
                ];
            }
            if ($comparison === 0) {
                return [
                    'verdict' => 'verified_fixed',
                    'patch_status' => 'verified_fixed',
                    'reason' => $target['kind'] === 'package'
                        ? 'The installed package inventory matches the exact sourced fixed vendor package build for this package subject; this does not prove a running worker maps to that package.'
                        : 'The running web worker maps to the exact sourced fixed vendor package build for the identified release.',
                ];
            }
            if ($comparison > 0) {
                return [
                    'verdict' => 'unknown',
                    'patch_status' => 'unknown',
                    'reason' => 'The installed vendor build is newer than the sourced fixed package but has no exact vendor rule in this advisory revision.',
                ];
            }

            if ($target['kind'] !== 'package'
                && (!$target['provenance_verified'] || $target['provenance_fact_id'] === null)) {
                return [
                    'verdict' => 'unknown',
                    'patch_status' => 'unknown',
                    'reason' => 'The installed vendor package is below the sourced fixed build, but executable/package ownership is not established for this runtime subject.',
                ];
            }

            $affectedSubject = match ($target['kind']) {
                'cli' => 'The CLI executable reports a runtime version matching the installed vendor package below the sourced fixed build.',
                'fpm-executable' => 'The FPM executable reports a runtime version matching the installed vendor package below the sourced fixed build.',
                default => 'The running web worker maps to a vendor package below the sourced fixed build for the identified release.',
            };
            return [
                'verdict' => 'potentially_affected',
                'patch_status' => 'potentially_affected',
                'reason' => $target['kind'] === 'package'
                    ? 'The installed package inventory is below the sourced fixed build for this package subject; active worker code identity is assessed separately.'
                    : $affectedSubject,
            ];
        }

        return [
            'verdict' => 'unknown',
            'patch_status' => 'unknown',
            'reason' => 'No exact vendor fixed-version rule matches the identified distribution release and package; an upstream version label alone does not establish package provenance or patch status.',
        ];
    }

    /**
     * @phpstan-param AdvisoryDefinition $advisory
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-param RuntimeTarget $target
     * @phpstan-param VendorRule|null $rule
     * @return 'true'|'false'|'unknown'
     */
    private function applicability(array $advisory, array $inventory, array $target, ?array $rule): string
    {
        if ($target['kind'] === 'unknown' || $target['deleted'] || $target['version'] === null) {
            return 'unknown';
        }

        if ($advisory['cve'] === 'CVE-2026-115560') {
            // The collector does not inspect .user.ini/Apache directory overrides or application code.
            return 'unknown';
        }

        if ($rule === null || !$target['provenance_verified'] || $target['provenance_fact_id'] === null
            || $target['package_version'] === null || $target['package'] === null) {
            return 'unknown';
        }

        $comparison = $this->compareVendorVersions($target['package_version'], $rule['fixed_version']);
        if ($comparison === null) {
            return 'unknown';
        }

        return $comparison < 0 ? 'true' : ($comparison === 0 ? 'false' : 'unknown');
    }

    private function compareVendorVersions(string $installed, string $fixed): ?int
    {
        $installed = trim($installed);
        $fixed = trim($fixed);
        if ($installed === '' || $fixed === '' || strlen($installed) > 256 || strlen($fixed) > 256
            || preg_match('/\A[0-9A-Za-z.+:~_-]+\z/', $installed) !== 1
            || preg_match('/\A[0-9A-Za-z.+:~_-]+\z/', $fixed) !== 1) {
            return null;
        }
        $installedBranch = $this->versionBranch($installed);
        $fixedBranch = $this->versionBranch($fixed);
        if ($installedBranch === null || $installedBranch !== $fixedBranch) {
            return null;
        }

        $installedUpstream = $this->upstreamVersion($installed);
        $fixedUpstream = $this->upstreamVersion($fixed);
        if ($installedUpstream === null || $fixedUpstream === null) {
            return null;
        }
        if ($installedUpstream === $fixedUpstream) {
            return $installed === $fixed ? 0 : null;
        }

        return version_compare($installedUpstream, $fixedUpstream);
    }

    private function versionBranch(mixed $version): ?string
    {
        if (!is_string($version) || preg_match('/\A(?:[0-9]+:)?([0-9]+\.[0-9]+)\./', trim($version), $matches) !== 1) {
            return null;
        }

        return $matches[1];
    }

    private function upstreamVersion(mixed $version): ?string
    {
        if (!is_string($version) || preg_match('/\A(?:[0-9]+:)?([0-9]+\.[0-9]+\.[0-9]+)/', trim($version), $matches) !== 1) {
            return null;
        }

        return $matches[1];
    }

    /**
     * @phpstan-param AdvisoryDefinition $advisory
     * @phpstan-param RuntimeTarget $target
     * @phpstan-param array{verdict: string, patch_status: string, reason: string} $basis
     * @phpstan-param VendorRule|null $rule
     */
    private function rationale(array $advisory, string $asOf, array $target, array $basis, ?array $rule): string
    {
        $version = $target['version'] !== null ? ' Runtime: ' . $target['version'] . '.' : ' Runtime version: unknown.';
        $package = $target['package'] !== null ? ' Package: ' . $target['package'] . ' ' . ($target['package_version'] ?? 'unknown') . '.' : ' Package provenance: unknown.';
        $source = ' Source: ' . ($rule['source_url'] ?? $advisory['source_url']) . ' (revision ' . ($rule['revision'] ?? $advisory['revision']) . '; pack as of ' . $asOf . ').';
        $guidance = [];
        foreach ($advisory['mitigations'] as $mitigation) {
            $guidance[] = $mitigation['setting'] . '=' . $mitigation['value'] . ' (' . $mitigation['effect'] . '; ' . $mitigation['source_url'] . ')';
        }
        $mitigations = $guidance === []
            ? ' No mitigation guidance is encoded for this advisory revision.'
            : ' Advisory mitigation guidance: ' . implode('; ', $guidance) . '. These measures are path-specific and do not establish a fixed patch or absence of compromise.';
        $rationale = $basis['reason'] . $version . $package . $source . $mitigations;

        return substr($rationale, 0, 1999);
    }

    /**
     * @param list<AdvisorySource> $sources
     * @param array<string, string> $sourceIds
     */
    private function addAdvisorySource(array &$sources, array &$sourceIds, string $url, string $capturedAt): string
    {
        if (isset($sourceIds[$url])) {
            return $sourceIds[$url];
        }
        $id = 'source.advisory.' . substr(hash('sha256', $url), 0, 20);
        $sources[] = [
            'source_id' => $id,
            'kind' => 'vendor_advisory',
            'locator' => $url,
            'captured_at' => $capturedAt,
            'captured_digest' => null,
            'current_digest' => null,
            'freshness' => 'unknown',
        ];
        $sourceIds[$url] = $id;

        return $id;
    }

    /** @param list<AdvisoryFact> $facts */
    private function addFact(array &$facts, string $key, mixed $value, string $sourceId): string
    {
        $id = 'fact.' . str_replace([' ', '/'], ['-', '.'], $key);
        if (strlen($id) > 128 || strlen($key) > 128) {
            throw new InvalidArgumentException('Advisory fact identifier exceeds the evidence schema bounds.');
        }
        $facts[] = ['fact_id' => $id, 'key' => $key, 'value' => $value, 'source_id' => $sourceId];

        return $id;
    }

    /** @phpstan-param list<RuntimeFact> $facts */
    private function factId(array $facts, string $key): ?string
    {
        foreach ($facts as $fact) {
            if ($fact['key'] === $key) {
                return $fact['fact_id'];
            }
        }

        return null;
    }

    /** @phpstan-param list<RuntimeFact> $facts */
    private function factSourceId(array $facts, string $key): ?string
    {
        foreach ($facts as $fact) {
            if ($fact['key'] === $key) {
                return $fact['source_id'];
            }
        }

        return null;
    }
}
