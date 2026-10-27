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
 * @phpstan-type RuntimeTarget array{id: string, kind: string, version: string|null, package: string|null, package_version: string|null, source_fact_id: string|null, package_fact_id: string|null, deleted: bool|null, provenance_verified: bool, provenance_fact_id: string|null}
 * @phpstan-type AdvisorySource array{source_id: string, kind: 'vendor_advisory'|'other', locator: string, captured_at: string, captured_digest: string|null, current_digest: null, freshness: 'unknown'}
 * @phpstan-type AdvisoryFact array{fact_id: string, key: string, value: mixed, source_id: string}
 * @phpstan-type AdvisoryAssessment array{record_type: 'assessment', schema_version: '1.0', record_id: string, subject_id: string, assessed_at: string, verdict: string, patch_status: string, patch_evidence_ids: list<string>, compromise_evidence: array{status: 'unknown', evidence_ids: list<string>}, rationale: string}
 * @phpstan-type AdvisoryEvaluation array{sources: list<AdvisorySource>, facts: list<AdvisoryFact>, assessments: list<AdvisoryAssessment>}
 */
final class AdvisoryEvaluator
{
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
            $targets[] = ['id' => 'web-runtime-unknown', 'kind' => 'unknown', 'version' => null, 'package' => null, 'package_version' => null, 'source_fact_id' => null, 'package_fact_id' => null, 'deleted' => false, 'provenance_verified' => false, 'provenance_fact_id' => null];
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
                $assessment = [
                    'record_type' => 'assessment',
                    'schema_version' => '1.0',
                    'record_id' => 'assessment:' . $advisory['cve'] . ':' . $targetId,
                    'subject_id' => 'local-host',
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
                $moduleName = basename($modulePath);
                $packageName = preg_match('/\Alibphp([0-9]+\.[0-9]+)\.so\z/', $moduleName, $matches) === 1
                    ? 'libapache2-mod-php' . $matches[1]
                    : null;
                $package = $this->findPackage($packages, $packageName);
                $targets[] = [
                    'provenance_verified' => false,
                    'provenance_fact_id' => null,
                    'id' => 'apache-' . $workerIndex . '-' . ($moduleIndex + 1),
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

        return array_slice($targets, 0, 32);
    }

    /**
     * @param list<array{name: string, version: string}> $packages
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
        $basename = basename($path);
        if ($distribution === 'alpine' && preg_match('/\Aphp-fpm(8[2-5])\z/', $basename, $matches) === 1) {
            return dirname($path) === '/usr/sbin' ? 'php' . $matches[1] . '-fpm' : null;
        }
        if (preg_match('/\Aphp-fpm(8\.[2-5])\z/', $basename, $matches) === 1) {
            return dirname($path) === '/usr/sbin' ? 'php' . $matches[1] . '-fpm' : null;
        }

        return $basename === 'php-fpm' && dirname($path) === '/usr/sbin' ? 'php-fpm' : null;
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
                $uploadSetting = $inventory['configuration_by_sapi'][$configurationSapi]['session.upload_progress.enabled'];
                $serializeSetting = $inventory['configuration_by_sapi'][$configurationSapi]['session.serialize_handler'];
                $settingsObserved = $uploadSetting['state'] === 'observed'
                    && $serializeSetting['state'] === 'observed';
            }
            $riskConfiguration = $knownWebRuntime
                && $this->hasCooccurringConfigurationObservations(
                    $uploadSetting,
                    ['1', 'on', 'true'],
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
                    'reason' => 'The running web worker maps to the exact sourced fixed vendor package build for the identified release.',
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
                'reason' => 'The running web worker maps to a vendor package below the sourced fixed build for the identified release.',
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
}
