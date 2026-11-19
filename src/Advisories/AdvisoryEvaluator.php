<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Advisories;

use InvalidArgumentException;
use voku\PhpRuntimeAudit\RuntimeInventory\RuntimeInventoryCollector;

/**
 * Evaluates vendor evidence conservatively; missing provenance never becomes a fix claim.
 *
 * @phpstan-import-type RuntimeInventory from RuntimeInventoryCollector
 * @phpstan-import-type AdvisoryDefinition from AdvisoryCatalog
 * @phpstan-import-type VendorRule from AdvisoryCatalog
 * @phpstan-import-type RuntimeFact from RuntimeInventoryCollector
 * @phpstan-import-type RuntimeConfigSetting from RuntimeInventoryCollector
 * @phpstan-type RuntimeTarget array{id: string, subject_id: string, kind: string, version: string|null, package: string|null, package_version: string|null, source_fact_id: string|null, package_fact_id: string|null, deleted: bool|null, provenance_verified: bool, provenance_fact_id: string|null}
 * @phpstan-type AdvisorySource array{source_id: string, kind: 'vendor_advisory'|'other', locator: string, captured_at: string, captured_digest: string|null, current_digest: null, freshness: 'unknown'}
 * @phpstan-type AdvisoryFact array{fact_id: string, key: string, value: mixed, source_id: string}
 * @phpstan-type AdvisoryAssessment array{record_type: 'assessment', schema_version: '1.0', record_id: string, subject_id: string, assessed_at: string, verdict: string, patch_status: string, patch_evidence_ids: list<string>, compromise_evidence: array{status: 'unknown', evidence_ids: list<string>}, rationale: string}
 * @phpstan-type AssessmentBasis array{verdict: string, patch_status: string, reason: string, configuration_exposure: array{state: string, reason: string, derived_from_fact_ids: list<string>, observed_files: list<string>}|null}
 * @phpstan-type AdvisoryEvaluation array{sources: list<AdvisorySource>, facts: list<AdvisoryFact>, assessments: list<AdvisoryAssessment>}
 */
final class AdvisoryEvaluator
{
    /** PHP ini boolean spellings (case-insensitive, trimmed). */
    private const INI_TRUE_VALUES = ['1', 'on', 'true', 'yes'];
    private const INI_FALSE_VALUES = ['0', 'off', 'false', 'no', 'none', ''];
    private const WEB_SAPIS = ['fpm', 'apache2'];

    /**
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-return AdvisoryEvaluation
     */
    public function evaluate(array $inventory, AdvisoryCatalog $catalog): array
    {
        $observedAt = $inventory['observed_at'];
        $targets = $this->runtimeTargets($inventory);
        /** @var list<RuntimeTarget> $targets */
        $targets = $targets;
        if ($targets === []) {
            $targets[] = ['id' => 'web-runtime-unknown', 'subject_id' => 'local-host', 'kind' => 'unknown', 'version' => null, 'package' => null, 'package_version' => null, 'source_fact_id' => null, 'package_fact_id' => null, 'deleted' => false, 'provenance_verified' => false, 'provenance_fact_id' => null];
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
        /** @var list<AdvisoryAssessment> $assessments */
        $assessments = [];
        $sourceIds = [];
        /** @var list<AdvisoryDefinition> $advisories */
        $advisories = $catalog->advisories;
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
                $targetId = $target['id'];
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
                $basisFact = $this->addFact(
                    $facts,
                    'advisory.' . $advisory['cve'] . '.' . $targetId . '.assessment_basis',
                    [
                        'as_of' => $catalog->asOf,
                        'revision' => $rule['revision'] ?? $advisory['revision'],
                        'source_url' => $rule['source_url'] ?? $advisory['source_url'],
                        'runtime_fact_id' => $target['source_fact_id'],
                        'package_fact_id' => $target['package_fact_id'],
                        'worker_package_provenance_fact_id' => $target['provenance_fact_id'],
                        'vendor_fact_ids' => $vendorEvidenceIds,
                        'vendor' => $inventory['distribution'],
                        'release' => $rule['release'] ?? $this->releaseName($inventory),
                        'package_manager' => $inventory['package_manager'],
                        'upstream_fixed_fact_id' => $fixedUpstreamFact,
                        'reason' => $basis['reason'],
                    ],
                    $sourceId,
                );
                if ($basis['configuration_exposure'] !== null) {
                    $this->addFact(
                        $facts,
                        'advisory.' . $advisory['cve'] . '.' . $targetId . '.configuration_exposure',
                        [
                            'state' => $basis['configuration_exposure']['state'],
                            'reason' => $basis['configuration_exposure']['reason'],
                            'independent_of' => ['patch_status', 'compromise_evidence'],
                            'derived_from_fact_ids' => $basis['configuration_exposure']['derived_from_fact_ids'],
                            'observed_files' => $basis['configuration_exposure']['observed_files'],
                        ],
                        $mainSourceId,
                    );
                }
                $evidenceIds = [];
                foreach ([
                    $target['source_fact_id'],
                    $target['package_fact_id'],
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

        return ['sources' => $sources, 'facts' => $facts, 'assessments' => $assessments];
    }

    /**
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-return list<RuntimeTarget>
     */
    private function runtimeTargets(array $inventory): array
    {
        $packages = $inventory['packages'];
        $facts = $inventory['facts'];
        $targets = [];
        foreach ($inventory['workers'] as $index => $worker) {
            $workerIndex = $index + 1;
            if ($worker['kind'] === 'fpm') {
                $executablePath = $worker['executable_path'];
                $packageName = $this->fpmPackageName($executablePath, $inventory['distribution'] ?? '');
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
                    'version' => $worker['version'],
                    'package' => $packageName,
                    'package_version' => $package['version'] ?? null,
                    'source_fact_id' => $this->factId($facts, 'worker.' . $workerIndex . '.version'),
                    'package_fact_id' => $package['fact_id'] ?? null,
                    'deleted' => $worker['executable_deleted'],
                ];
                continue;
            }
            if ($worker['apache_php_modules'] === null) {
                continue;
            }
            foreach ($worker['apache_php_modules'] as $moduleIndex => $modulePath) {
                // The loaded module's filename does not reliably encode its version (modern
                // builds ship an unversioned libphp.so); dpkg-confirmed provenance of the exact
                // loaded path is authoritative when available, with the filename guess as a
                // fallback for hosts without local package-database confirmation.
                $moduleProvenance = $worker['package_provenance']['verified']
                    && $worker['package_provenance']['executable_path'] === $modulePath;
                $moduleName = basename($modulePath);
                $packageName = $moduleProvenance
                    ? $worker['package_provenance']['package_name']
                    : (preg_match('/\Alibphp([0-9]+\.[0-9]+)\.so\z/', $moduleName, $matches) === 1
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
                    // Package inventory is installed-state evidence. It cannot establish which
                    // mod_php binary is still mapped into an already-running Apache process.
                    'version' => null,
                    'package' => $packageName,
                    'package_version' => $package['version'] ?? null,
                    'source_fact_id' => $this->factId($facts, 'worker.' . $workerIndex . '.apache_php_modules'),
                    'package_fact_id' => $package['fact_id'] ?? null,
                    'deleted' => $worker['apache_php_module_deleted'] === true,
                ];
            }
        }

        $runtimeIndex = 0;
        foreach ($inventory['runtimes'] as $runtime) {
            ++$runtimeIndex;
            if (!is_string($runtime['id'] ?? null)
                || !is_string($runtime['binary_path'] ?? null)
                || !is_string($runtime['version'] ?? null)) {
                continue;
            }
            $packageName = $this->cliPackageName($runtime['binary_path'], $inventory['distribution'] ?? '');
            $package = $this->findPackage($packages, $packageName);
            $targets[] = [
                'id' => $runtime['id'], 'subject_id' => $runtime['id'], 'kind' => 'cli',
                'version' => $runtime['version'], 'package' => $packageName,
                'package_version' => $package['version'] ?? null,
                'source_fact_id' => $this->factId($facts, 'runtime.cli.' . $runtimeIndex . '.version'),
                'package_fact_id' => $package['fact_id'] ?? null, 'deleted' => false,
                'provenance_verified' => false, 'provenance_fact_id' => null,
            ];
        }

        foreach ($packages as $index => $package) {
            if (!$this->isRuntimePackageName($package['name'])) {
                continue;
            }
            $packageId = 'package-' . substr(hash('sha256', $package['name'] . "\0" . $package['version']), 0, 20);
            $packageFactId = $this->factId($facts, 'package.' . $index . '.version');
            $targets[] = [
                'id' => $packageId, 'subject_id' => $packageId, 'kind' => 'package',
                'version' => $this->upstreamVersion($package['version']), 'package' => $package['name'],
                'package_version' => $package['version'], 'source_fact_id' => $packageFactId,
                'package_fact_id' => $packageFactId, 'deleted' => false,
                'provenance_verified' => $inventory['package_inventory_state'] === 'attempted' && $packageFactId !== null,
                'provenance_fact_id' => $packageFactId,
            ];
        }

        return array_slice($targets, 0, 512);
    }

    /** @param list<array{name: string, version: string}> $packages
     * @return array{version: string, fact_id: string}|null
     */
    private function findPackage(array $packages, ?string $name): ?array
    {
        if ($name === null) {
            return null;
        }
        $matches = [];
        foreach ($packages as $index => $package) {
            if ($package['name'] === $name) {
                $matches[$package['version']][] = ['version' => $package['version'], 'fact_id' => 'fact.package.' . $index . '.version'];
            }
        }
        if (count($matches) !== 1) {
            return null;
        }
        return array_values($matches)[0][0];
    }

    private function cliPackageName(string $path, string $distribution): ?string
    {
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

    private function isRuntimePackageName(string $name): bool
    {
        return preg_match('/\Aphp[0-9]{2,3}-php-(?:cli|fpm|cgi)\z/', $name) === 1
            || preg_match('/\Aphp(?:[0-9]+(?:\.[0-9]+)?|[0-9]{2,3})?-(?:cli|fpm|cgi)\z/', $name) === 1
            || preg_match('/\Alibapache2-mod-php(?:[0-9]+(?:\.[0-9]+)?)?\z/', $name) === 1
            || preg_match('/\Aphp[0-9]{2,3}\z/', $name) === 1;
    }

    /**
     * Select config observations only when their path identifies this PHP branch.
     * Generic roots are usable only when there is a single known web runtime branch.
     *
     * @phpstan-param RuntimeConfigSetting $setting
     * @phpstan-param RuntimeTarget $target
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-return RuntimeConfigSetting
     */
    private function configurationForTarget(array $setting, array $target, array $inventory): array
    {
        $branch = $this->versionBranch($target['version'] ?? $target['package_version']);
        if ($branch === null) {
            return ['value' => null, 'state' => 'unknown', 'files' => [], 'observations' => []];
        }
        $compactBranch = str_replace('.', '', $branch);
        $roots = [];
        foreach ($setting['observations'] as $observation) {
            $root = $observation['configuration_root'];
            if (!is_string($root)) {
                continue;
            }
            if (preg_match('#(?:\A|/)php/' . preg_quote($branch, '#') . '/fpm\z#', $root) === 1
                || preg_match('#(?:\A|/)php' . preg_quote($compactBranch, '#') . '(?:/|\z)#', $root) === 1) {
                $roots[$root] = true;
            }
        }
        if (count($roots) !== 1) {
            $allRoots = [];
            foreach ($setting['observations'] as $observation) {
                if (is_string($observation['configuration_root'])) {
                    $allRoots[$observation['configuration_root']] = true;
                }
            }
            if ($roots !== [] || count($allRoots) !== 1 || $this->fpmBranches($inventory) !== [$branch]) {
                return ['value' => null, 'state' => 'unknown', 'files' => [], 'observations' => []];
            }
            $roots = $allRoots;
        }
        $root = array_key_first($roots);
        $observations = array_values(array_filter(
            $setting['observations'],
            static fn(array $observation): bool => $observation['configuration_root'] === $root,
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

    /** @phpstan-param RuntimeInventory $inventory
     * @return list<string>
     */
    private function fpmBranches(array $inventory): array
    {
        $branches = [];
        foreach ($inventory['workers'] as $worker) {
            if ($worker['kind'] === 'fpm') {
                $branch = $this->versionBranch($worker['version']);
                if ($branch !== null) {
                    $branches[$branch] = true;
                }
            } elseif ($worker['apache_php_modules'] !== null) {
                $resolved = false;
                foreach ($worker['apache_php_modules'] as $modulePath) {
                    if (preg_match('/\Alibphp([0-9]+\.[0-9]+)\.so\z/', basename($modulePath), $matches) === 1) {
                        $branches[$matches[1]] = true;
                        $resolved = true;
                    }
                }
                // Filename-based detection fails on unversioned module builds (e.g. libphp.so);
                // fall back to a dpkg-confirmed provenance match for the exact loaded module.
                if (!$resolved && $worker['package_provenance']['verified']
                    && in_array($worker['package_provenance']['executable_path'], $worker['apache_php_modules'], true)) {
                    $branch = $this->versionBranch($worker['package_provenance']['package_version']);
                    if ($branch !== null) {
                        $branches[$branch] = true;
                    }
                }
            }
        }
        foreach ($inventory['packages'] as $package) {
            if (!is_string($package['name'] ?? null) || !is_string($package['version'] ?? null)) {
                continue;
            }
            if (preg_match('/\Aphp[0-9]{2,3}-php-fpm\z/', $package['name']) === 1
                || preg_match('/\Aphp(?:[0-9]+\.[0-9]+)?-fpm\z/', $package['name']) === 1
                || preg_match('/\Aphp[0-9]{2,3}-fpm\z/', $package['name']) === 1) {
                $branch = $this->versionBranch($package['version']);
            } elseif (preg_match('/\Alibapache2-mod-php([0-9]+\.[0-9]+)\z/', $package['name'], $matches) === 1) {
                $branch = $matches[1];
            } else {
                $branch = null;
            }
            if ($branch !== null) {
                $branches[$branch] = true;
            }
        }
        $result = array_keys($branches);
        sort($result, SORT_STRING);
        return $result;
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
            if (!in_array(strtolower(trim($firstObservation['value'])), $firstExpected, true)) {
                continue;
            }
            foreach ($secondSetting['observations'] as $secondObservation) {
                if (!in_array(strtolower(trim($secondObservation['value'])), $secondExpected, true)) {
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
     * @phpstan-return AssessmentBasis
     */
    private function assess(array $advisory, array $inventory, array $target, ?array $rule): array
    {
        // Patch status, configuration exposure and compromise are independent axes. The patch
        // axis always comes from the same conservative vendor/provenance path and is never changed
        // by configuration. Configuration exposure is its own fact (not patch evidence); it can only
        // turn an unknown or verified_fixed verdict into needs_investigation.
        $patch = $this->patchAssessment($inventory, $target, $rule);

        $configurationSapi = match ($target['kind']) {
            'fpm' => 'fpm',
            'apache-mod-php' => 'apache2',
            default => null,
        };

        if ($advisory['cve'] === 'CVE-2026-126714') {
            $handlerSetting = $configurationSapi === null
                ? ['value' => null, 'state' => 'unknown', 'files' => [], 'observations' => []]
                : $this->configurationForTarget(
                    $inventory['configuration_by_sapi'][$configurationSapi]['session.save_handler'],
                    $target,
                    $inventory,
                );
            // Any observed files selection for this runtime (including a global value that pools
            // may inherit while another pool overrides it) is enough to ask for investigation.
            $filesConfigured = in_array(
                'files',
                array_map(static fn(array $observation): string => strtolower(trim($observation['value'])), $handlerSetting['observations']),
                true,
            );
            $caveat = ' Applications can register their own save handler (session_set_save_handler or framework session storage), which overrides session.save_handler, and disabling upload progress is only a partial measure because applications can store untrusted data in file-backed sessions independently.';

            return $patch + ['configuration_exposure' => [
                // Configuration can point at the affected backend but can never rule it out.
                'state' => $filesConfigured ? 'needs_investigation' : 'unknown',
                'reason' => ($filesConfigured
                    ? 'The inspected configuration selects the affected files session backend for this runtime or for some of its pools.'
                    : ($configurationSapi === null
                        ? 'No PHP web runtime was identified for this subject.'
                        : 'The inspected configuration does not establish a non-files session backend for this runtime (PHP defaults to files when session.save_handler is unset).'))
                    . $caveat,
                'derived_from_fact_ids' => $this->configurationFactIds($inventory, $configurationSapi, ['session.save_handler']),
                'observed_files' => $handlerSetting['files'],
            ]];
        }

        if ($advisory['cve'] === 'CVE-2026-115560') {
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
            // not_observed only means the collected configuration has upload progress disabled; it
            // is not store-wide proof and never clears a verified fix into a no-action verdict.
            $uploadProgressDisabled = $settingsObserved
                && is_string($uploadSetting['value'])
                && in_array(strtolower(trim($uploadSetting['value'])), self::INI_FALSE_VALUES, true);
            $sameContextRisk = $knownWebRuntime
                && $this->hasCooccurringConfigurationObservations(
                    $uploadSetting,
                    self::INI_TRUE_VALUES,
                    $serializeSetting,
                    ['php_binary', 'php_serialize'],
                );
            $unresolvedStoreContexts = false;
            $sharedStoreMismatch = $configurationSapi === null || $sameContextRisk
                ? null
                : $this->sharedStoreSerializerMismatch($inventory, $configurationSapi, $target, $unresolvedStoreContexts);
            $riskConfiguration = $sameContextRisk || $sharedStoreMismatch !== null;
            if ($sameContextRisk) {
                $reason = 'One or more inspected web-SAPI configuration sources contain upload progress enabled and a serialization handler named in the advisory; precedence, per-pool applicability, application code, request path, and runtime handler changes remain unverified.';
            } elseif ($sharedStoreMismatch !== null) {
                $reason = $sharedStoreMismatch;
            } elseif (!$knownWebRuntime) {
                $reason = 'No PHP web runtime was identified; configuration alone cannot establish that the described path is reachable.';
            } elseif (!$settingsObserved) {
                $reason = 'Relevant configuration is missing or conflicting; .user.ini or Apache per-directory overrides and application code changes are not observed.';
            } elseif (!$uploadProgressDisabled) {
                $reason = 'Upload progress is enabled in the inspected configuration without an observed same-context or shared-store serializer mismatch, but applications can register their own save handler or store, and readers or writers outside the inspected configuration are not collected, so a cross-store serializer mismatch cannot be excluded.';
            } else {
                $reason = 'Inspected configuration has upload progress disabled, but administrative scope (php_admin_value), .user.ini or Apache per-directory overrides, other writers of the same session store, and application code are not established; applicability remains unknown.';
            }

            $exposure = [
                'state' => $riskConfiguration
                    ? 'needs_investigation'
                    // A web context with conflicting session values could share the store unseen.
                    : ($knownWebRuntime && $uploadProgressDisabled && !$unresolvedStoreContexts ? 'not_observed' : 'unknown'),
                'reason' => $reason,
                'derived_from_fact_ids' => $this->configurationFactIds(
                    $inventory,
                    $configurationSapi,
                    $sharedStoreMismatch !== null
                        ? ['session.upload_progress.enabled', 'session.serialize_handler', 'session.save_handler', 'session.save_path']
                        : ['session.upload_progress.enabled', 'session.serialize_handler'],
                ),
                'observed_files' => array_values(array_unique([...$uploadSetting['files'], ...$serializeSetting['files']])),
            ];
            if ($riskConfiguration && $patch['patch_status'] === 'potentially_affected') {
                // Keep the upgrade action: remediation is driven by the verdict, so an unpatched
                // runtime must not be downgraded to a configuration-only finding.
                return [
                    'verdict' => 'potentially_affected',
                    'patch_status' => 'potentially_affected',
                    'reason' => $patch['reason'] . ' Configuration exposure (assessed separately, also needs investigation): ' . $reason,
                    'configuration_exposure' => $exposure,
                ];
            }
            if ($riskConfiguration) {
                return [
                    'verdict' => 'needs_investigation',
                    'patch_status' => $patch['patch_status'],
                    'reason' => $reason
                        . ($patch['patch_status'] === 'verified_fixed'
                            ? ' The verified fix does not make an explicitly enabled upload-progress path safe when readers and writers of the same session store use different serialization handlers.'
                            : '')
                        . ' Patch evidence (assessed separately): ' . $patch['reason'],
                    'configuration_exposure' => $exposure,
                ];
            }

            if ($patch['verdict'] === 'verified_fixed') {
                // A verified fix never becomes a no-action result for this advisory: it requires
                // matching serializers (or upload progress administratively disabled) across every
                // writer of a shared session store even after the update. The collector cannot
                // establish php_admin_value scope, .user.ini/.htaccess overrides, or other store
                // writers, so even locally disabled upload progress is not store-wide proof.
                return [
                    'verdict' => 'needs_investigation',
                    'patch_status' => 'verified_fixed',
                    'reason' => 'The patch is verified, but the advisory requires every reader and writer of a shared session store to use the same serialization handler, or upload progress to be administratively disabled for all of them, even after the update; administrative scope, per-directory overrides and other store writers are not collected. Configuration exposure (assessed separately): ' . $reason
                        . ' Patch evidence (assessed separately): ' . $patch['reason'],
                    'configuration_exposure' => $exposure,
                ];
            }

            return [
                'verdict' => $patch['verdict'],
                'patch_status' => $patch['patch_status'],
                'reason' => $patch['reason'] . ' Configuration exposure (assessed separately): ' . $reason,
                'configuration_exposure' => $exposure,
            ];
        }

        return $patch + ['configuration_exposure' => null];
    }

    /**
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-param RuntimeTarget $target
     * @phpstan-param VendorRule|null $rule
     * @phpstan-return array{verdict: string, patch_status: string, reason: string}
     */
    private function patchAssessment(array $inventory, array $target, ?array $rule): array
    {
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
                return [
                    'verdict' => 'unknown',
                    'patch_status' => 'unknown',
                    'reason' => 'The installed package matches the sourced fixed build, but ownership, integrity and loaded worker identity have not been established. Package inventory and matching upstream versions alone cannot prove a running fix.',
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

            return [
                'verdict' => 'potentially_affected',
                'patch_status' => 'potentially_affected',
                'reason' => $target['kind'] === 'package'
                    ? 'The installed package inventory is below the sourced fixed build for this package subject; active worker code identity is assessed separately.'
                    : 'The running web worker maps to a vendor package below the sourced fixed build for the identified release.',
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
     * @phpstan-param AssessmentBasis $basis
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

        $rationale = substr($rationale, 0, 1999);
        // Never end inside a multibyte character: invalid UTF-8 would abort report encoding.
        for ($trim = 0; $trim < 3 && preg_match('//u', $rationale) !== 1; ++$trim) {
            $rationale = substr($rationale, 0, -1);
        }

        return preg_match('//u', $rationale) === 1 ? $rationale : (string) preg_replace('/[^\x20-\x7E]/', '?', $rationale);
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

    /**
     * Inventory facts a configuration-exposure judgment was derived from. Shared-store
     * correlation reads every web SAPI, so it cites both SAPIs' facts for those settings.
     *
     * @phpstan-param RuntimeInventory $inventory
     * @param list<string> $settings
     * @return list<string>
     */
    private function configurationFactIds(array $inventory, ?string $sapi, array $settings): array
    {
        if ($sapi === null) {
            return [];
        }
        $sapis = array_intersect($settings, ['session.save_handler', 'session.save_path']) !== [] && count($settings) > 1
            ? self::WEB_SAPIS
            : [$sapi];
        $ids = [];
        foreach ($sapis as $factSapi) {
            foreach ($settings as $setting) {
                $id = $this->factId($inventory['facts'], 'configuration.' . $factSapi . '.' . $setting);
                if ($id !== null) {
                    $ids[] = $id;
                }
            }
        }

        return $ids;
    }

    /**
     * Debian/Ubuntu PHP packages of every version and SAPI (/etc/php/X.Y/{fpm,apache2}) are built
     * with the same default session.save_path (/var/lib/php/sessions), so the default resolves to
     * that path and groups with an explicit spelling of it. Other installs (source builds,
     * containers, RHEL/Remi) keep a per-install default.
     */
    private function defaultSessionStore(string $sapi, string $root): string
    {
        if (preg_match('#\A/etc/php/[0-9]+\.[0-9]+/(?:fpm|apache2)\z#', $root) === 1) {
            return '/var/lib/php/sessions';
        }

        return "default\0" . $sapi . "\0" . $root;
    }

    /**
     * Correlate session stores across web contexts (FPM pools, per-root globals, Apache).
     * A context's effective value is its own observation, else its root's global value, else
     * PHP's default. Contexts whose configured store matches (or that all use the default
     * location) and whose serializers differ, while at least one of them explicitly enables
     * upload progress, are reported. This is a correlation hint from configuration files only:
     * a match raises an investigation, a non-match never clears anything.
     *
     * @phpstan-param RuntimeInventory $inventory
     * @phpstan-param RuntimeTarget $target
     */
    private function sharedStoreSerializerMismatch(array $inventory, string $targetSapi, array $target, bool &$unresolved = false): ?string
    {
        $unresolved = false;
        $settings = ['session.upload_progress.enabled', 'session.serialize_handler', 'session.save_handler', 'session.save_path'];
        $targetRoots = [];
        foreach ($settings as $setting) {
            $selected = $this->configurationForTarget($inventory['configuration_by_sapi'][$targetSapi][$setting], $target, $inventory);
            foreach ($selected['observations'] as $observation) {
                if (is_string($observation['configuration_root'])) {
                    $targetRoots[$observation['configuration_root']] = true;
                }
            }
        }
        if ($targetRoots === []) {
            return null;
        }

        // values[sapi][root][context][setting] = list of observed values
        $values = [];
        foreach (['fpm', 'apache2'] as $sapi) {
            $sapiSettings = $inventory['configuration_by_sapi'][$sapi];
            foreach ($settings as $setting) {
                foreach ($sapiSettings[$setting]['observations'] as $observation) {
                    if (!is_string($observation['configuration_root'])) {
                        continue;
                    }
                    $values[$sapi][$observation['configuration_root']][$observation['context']][$setting][] = trim($observation['value']);
                }
            }
        }

        $groups = [];
        foreach ($values as $sapi => $roots) {
            foreach ($roots as $root => $contexts) {
                $global = $contexts['global'] ?? [];
                // The global section stays a member even when pools exist: pools without session
                // directives are not emitted by the collector but inherit exactly these values.
                // If every pool overrides them this can over-report, which only raises a result.
                $contextNames = array_keys($contexts);
                if (!in_array('global', $contextNames, true)) {
                    $contextNames[] = 'global';
                }
                foreach ($contextNames as $context) {
                    $effective = [];
                    foreach ($settings as $setting) {
                        $observed = array_values(array_unique($contexts[$context][$setting] ?? $global[$setting] ?? []));
                        if (count($observed) > 1) {
                            $unresolved = true; // conflicting values: this context cannot be judged.
                            continue 2;
                        }
                        $effective[$setting] = $observed[0] ?? null;
                    }
                    $handler = strtolower($effective['session.save_handler'] ?? 'files');
                    $path = $effective['session.save_path'];
                    if ($path !== null && preg_match('#\A(?:[0-9]{1,3};(?:[0-7]{3,4};)?)?(/.*)\z#', $path, $pathMatch) === 1) {
                        // The files handler's "N;" / "N;MODE;" prefix does not change the directory.
                        $path = rtrim($pathMatch[1], '/') ?: '/';
                    }
                    // An unset save_path resolves to a build-specific default: shared within one
                    // install, and across Debian/Ubuntu packages (see defaultSessionStore()).
                    $store = $handler . "\0" . ($path === null || $path === ''
                        ? $this->defaultSessionStore($sapi, (string) $root)
                        : $path);
                    $groups[$store][] = [
                        // Root and pool names come from the host: keep them printable ASCII and bounded.
                        'label' => substr((string) preg_replace('/[^\x20-\x7E]/', '?', $sapi . ':' . $root . ':' . ($context === 'global' && count($contexts) > 1 ? 'global (pools without overrides)' : $context)), 0, 120),
                        'is_target' => $sapi === $targetSapi && isset($targetRoots[(string) $root]),
                        'upload_enabled' => in_array(strtolower((string) $effective['session.upload_progress.enabled']), self::INI_TRUE_VALUES, true),
                        'serializer' => strtolower($effective['session.serialize_handler'] ?? 'php'),
                        'default_location' => $path === null || $path === '',
                    ];
                }
            }
        }

        foreach ($groups as $members) {
            // The advisory requires identical serializers for every reader and writer of a
            // shared store while upload progress is enabled, so any difference is reported.
            $writers = array_filter($members, static fn(array $member): bool => $member['upload_enabled']);
            if ($writers === [] || count(array_unique(array_column($members, 'serializer'))) < 2
                || !in_array(true, array_column($members, 'is_target'), true)) {
                continue;
            }
            $labels = array_slice(array_map(
                static fn(array $member): string => $member['label'] . ' (serializer ' . $member['serializer'] . ($member['upload_enabled'] ? ', upload progress enabled' : '') . ')',
                $members,
            ), 0, 8);
            $sharing = $members[0]['default_location']
                ? 'appear to share one default session location (session.save_path unset: pools of one install share its default, and Debian/Ubuntu packages of every SAPI and version share /var/lib/php/sessions; separate pools do not imply separate storage)'
                : 'configure the same session store';

            return 'Inspected web contexts ' . $sharing . ' with different serialization handlers while upload progress is explicitly enabled in at least one of them; the advisory requires identical handlers for every reader and writer of the store: '
                . implode('; ', $labels)
                . '. This comes from configuration files only; applications can register their own save handler or store, and precedence and per-directory overrides remain unverified.';
        }

        return null;
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
}
