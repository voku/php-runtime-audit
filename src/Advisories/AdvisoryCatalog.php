<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Advisories;

use InvalidArgumentException;
use RuntimeException;
use voku\PhpRuntimeAudit\Evidence\DuplicateJsonKeyGuard;

/**
 * @phpstan-type VendorRule array{vendor: string, release: string, package_names: list<string>, fixed_version: string, source_url: string, revision: string}
 * @phpstan-type AdvisoryMitigation array{setting: string, value: string, effect: string, source_url: string}
 * @phpstan-type AdvisoryDefinition array{cve: string, title: string, source_url: string, revision: string, fixed_upstream: array<string, string>, mitigations: list<AdvisoryMitigation>, vendor_rules: list<VendorRule>}
 */
final readonly class AdvisoryCatalog
{
    /** @phpstan-var list<AdvisoryDefinition> */
    public array $advisories;

    /**
     * @phpstan-param list<AdvisoryDefinition> $advisories
     */
    private function __construct(
        public string $asOf,
        public string $digest,
        public string $loadedAt,
        array $advisories,
    ) {
        $this->advisories = $advisories;
    }

    public static function defaultPath(): string
    {
        return dirname(__DIR__, 2) . '/resources/advisories/php2shell/v1.json';
    }

    public static function load(?string $path = null): self
    {
        $path ??= self::defaultPath();
        $size = @filesize($path);
        if (!is_file($path) || is_link($path) || !is_int($size) || $size > 262_144) {
            throw new RuntimeException('Advisory catalog is missing, linked, or exceeds its size limit.');
        }
        $json = @file_get_contents($path, false, null, 0, 262_145);
        if (!is_string($json) || strlen($json) > 262_144) {
            throw new RuntimeException('Advisory catalog could not be read.');
        }
        DuplicateJsonKeyGuard::assertNoDuplicates($json);
        $data = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($data) || ($data['schema_version'] ?? null) !== '1.0' || !is_string($data['as_of'] ?? null) || !is_array($data['advisories'] ?? null)) {
            throw new InvalidArgumentException('Advisory catalog has an unsupported structure.');
        }
        if (preg_match('/\A[0-9]{4}-[0-9]{2}-[0-9]{2}\z/', $data['as_of']) !== 1 || !array_is_list($data['advisories']) || count($data['advisories']) > 64) {
            throw new InvalidArgumentException('Advisory catalog metadata is invalid.');
        }

        /** @var list<mixed> $rawAdvisories */
        $rawAdvisories = $data['advisories'];
        $ids = [];
        $advisories = [];
        foreach ($rawAdvisories as $rawAdvisory) {
            $advisory = self::validateAdvisory($rawAdvisory);
            if (in_array($advisory['cve'], $ids, true)) {
                throw new InvalidArgumentException('Advisory catalog contains a duplicate CVE.');
            }
            $ids[] = $advisory['cve'];
            $advisories[] = $advisory;
        }

        return new self($data['as_of'], 'sha256:' . hash('sha256', $json), gmdate('Y-m-d\TH:i:s\Z'), $advisories);
    }

    /** @return AdvisoryDefinition */
    private static function validateAdvisory(mixed $advisory): array
    {
        if (!is_array($advisory)) {
            throw new InvalidArgumentException('Advisory entry is invalid.');
        }

        $cve = $advisory['cve'] ?? null;
        $title = $advisory['title'] ?? null;
        $sourceUrl = $advisory['source_url'] ?? null;
        $revision = $advisory['revision'] ?? null;
        $fixedUpstream = $advisory['fixed_upstream'] ?? null;
        $rawMitigations = $advisory['mitigations'] ?? null;
        $rawVendorRules = $advisory['vendor_rules'] ?? null;
        if (!is_string($cve) || preg_match('/\ACVE-[0-9]{4}-[0-9]{4,}\z/', $cve) !== 1
            || !is_string($title) || $title === '' || strlen($title) > 256
            || !is_string($sourceUrl) || !self::isSourceUrl($sourceUrl)
            || !is_string($revision) || !preg_match('/\A[0-9]{4}-[0-9]{2}-[0-9]{2}\z/', $revision)
            || !is_array($fixedUpstream)
            || !is_array($rawMitigations) || !array_is_list($rawMitigations)
            || !is_array($rawVendorRules) || !array_is_list($rawVendorRules)) {
            throw new InvalidArgumentException('Advisory entry is invalid.');
        }

        $normalizedFixedUpstream = [];
        foreach ($fixedUpstream as $branch => $version) {
            if (!is_string($branch) || !preg_match('/\A8\.[2-5]\z/', $branch) || !is_string($version) || !preg_match('/\A[0-9]+\.[0-9]+\.[0-9]+\z/', $version)) {
                throw new InvalidArgumentException('Upstream fixed-version entry is invalid.');
            }
            $normalizedFixedUpstream[$branch] = $version;
        }

        $mitigations = [];
        foreach ($rawMitigations as $mitigation) {
            if (!is_array($mitigation)
                || !is_string($mitigation['setting'] ?? null)
                || !is_string($mitigation['value'] ?? null)
                || !is_string($mitigation['effect'] ?? null)
                || !is_string($mitigation['source_url'] ?? null)
                || !self::isSourceUrl($mitigation['source_url'])) {
                throw new InvalidArgumentException('Advisory mitigation entry is invalid.');
            }
            $mitigations[] = [
                'setting' => $mitigation['setting'],
                'value' => $mitigation['value'],
                'effect' => $mitigation['effect'],
                'source_url' => $mitigation['source_url'],
            ];
        }

        $vendorRules = [];
        foreach ($rawVendorRules as $rule) {
            if (!is_array($rule)
                || !is_string($rule['vendor'] ?? null)
                || !is_string($rule['release'] ?? null)
                || !is_array($rule['package_names'] ?? null)
                || !array_is_list($rule['package_names'])
                || !is_string($rule['fixed_version'] ?? null)
                || !is_string($rule['source_url'] ?? null)
                || !self::isSourceUrl($rule['source_url'])
                || !is_string($rule['revision'] ?? null)
                || !preg_match('/\A[0-9]{4}-[0-9]{2}-[0-9]{2}\z/', $rule['revision'])) {
                throw new InvalidArgumentException('Vendor fixed-version rule is invalid.');
            }
            foreach ($rule['package_names'] as $name) {
                if (!is_string($name) || preg_match('/\A[A-Za-z0-9][A-Za-z0-9.+:-]{0,127}\z/', $name) !== 1) {
                    throw new InvalidArgumentException('Vendor package name is invalid.');
                }
            }
            $vendorRules[] = [
                'vendor' => $rule['vendor'],
                'release' => $rule['release'],
                'package_names' => $rule['package_names'],
                'fixed_version' => $rule['fixed_version'],
                'source_url' => $rule['source_url'],
                'revision' => $rule['revision'],
            ];
        }

        return [
            'cve' => $cve,
            'title' => $title,
            'source_url' => $sourceUrl,
            'revision' => $revision,
            'fixed_upstream' => $normalizedFixedUpstream,
            'mitigations' => $mitigations,
            'vendor_rules' => $vendorRules,
        ];
    }

    private static function isSourceUrl(string $url): bool
    {
        return strlen($url) <= 2048
            && filter_var($url, FILTER_VALIDATE_URL) !== false
            && parse_url($url, PHP_URL_SCHEME) === 'https';
    }
}
