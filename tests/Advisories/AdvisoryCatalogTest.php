<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\Advisories;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use voku\PhpRuntimeAudit\Advisories\AdvisoryCatalog;

/**
 * @phpstan-import-type AdvisoryDefinition from AdvisoryCatalog
 */
final class AdvisoryCatalogTest extends TestCase
{
    public function test_bundled_catalog_carries_the_november_upstream_thresholds(): void
    {
        $catalog = AdvisoryCatalog::load();
        $advisories = $this->byCve($catalog);
        $expected = ['8.2' => '8.2.36', '8.3' => '8.3.37', '8.4' => '8.4.28', '8.5' => '8.5.13'];

        self::assertSame('2026-11-19', $catalog->asOf);
        foreach (['CVE-2026-115560', 'CVE-2026-126714'] as $cve) {
            self::assertArrayHasKey($cve, $advisories);
            self::assertSame($expected, $advisories[$cve]['fixed_upstream']);
            self::assertSame('2026-11-19', $advisories[$cve]['revision']);
            self::assertStringStartsWith('https://github.com/php/php-src/security/advisories/GHSA-', $advisories[$cve]['source_url']);
            // Vendor backports must be sourced individually; none are encoded for November yet.
            self::assertSame([], $advisories[$cve]['vendor_rules']);
        }
        // October advisories keep their own revisions and thresholds.
        self::assertSame('2026-10-21', $advisories['CVE-2026-109618']['revision']);
        self::assertSame('8.2.35', $advisories['CVE-2026-109618']['fixed_upstream']['8.2']);
    }

    public function test_cve_126714_upload_progress_mitigation_is_only_partial(): void
    {
        $advisory = $this->byCve(AdvisoryCatalog::load())['CVE-2026-126714'];

        self::assertNotSame([], $advisory['mitigations']);
        foreach ($advisory['mitigations'] as $mitigation) {
            self::assertSame('partial', $mitigation['effect']);
        }
    }

    /** @return iterable<string, array{string, string}> */
    public static function acceptedBranches(): iterable
    {
        yield 'supported branch' => ['8.4', '8.4.28'];
        yield 'new GA branch' => ['8.6', '8.6.0'];
        yield 'future major' => ['9.0', '9.0.1'];
        yield 'two-digit minor' => ['8.10', '8.10.3'];
    }

    #[DataProvider('acceptedBranches')]
    public function test_branch_support_is_data_driven(string $branch, string $version): void
    {
        $catalog = $this->loadWithFixedUpstream([$branch => $version]);

        self::assertSame([$branch => $version], $catalog->advisories[0]['fixed_upstream']);
    }

    /** @return iterable<string, array{array<mixed>}> */
    public static function rejectedBranches(): iterable
    {
        yield 'version on another branch' => [['8.5' => '8.6.0']];
        yield 'prefix-only branch match' => [['8.1' => '8.10.0']];
        yield 'pre-release is not a fixed release' => [['8.6' => '8.6.0RC1']];
        yield 'patch-level branch key' => [['8.6.0' => '8.6.0']];
        yield 'leading zero major' => [['08.6' => '08.6.0']];
        yield 'leading zero minor' => [['8.06' => '8.06.1']];
        yield 'leading zero patch' => [['8.4' => '8.4.028']];
        yield 'list instead of map' => [['8.6.0']];
    }

    /** @param array<mixed> $fixedUpstream */
    #[DataProvider('rejectedBranches')]
    public function test_inconsistent_branch_entries_are_rejected(array $fixedUpstream): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->loadWithFixedUpstream($fixedUpstream);
    }

    /** @return array<string, AdvisoryDefinition> */
    private function byCve(AdvisoryCatalog $catalog): array
    {
        $result = [];
        foreach ($catalog->advisories as $advisory) {
            $result[$advisory['cve']] = $advisory;
        }

        return $result;
    }

    /** @param array<mixed> $fixedUpstream */
    private function loadWithFixedUpstream(array $fixedUpstream): AdvisoryCatalog
    {
        $data = [
            'schema_version' => '1.0',
            'as_of' => '2026-11-19',
            'advisories' => [[
                'cve' => 'CVE-2026-000001',
                'title' => 'Synthetic advisory',
                'source_url' => 'https://example.invalid/advisory',
                'revision' => '2026-11-19',
                'fixed_upstream' => $fixedUpstream,
                'mitigations' => [],
                'vendor_rules' => [],
            ]],
        ];
        $path = sys_get_temp_dir() . '/pra-catalog-test-' . bin2hex(random_bytes(8)) . '.json';
        file_put_contents($path, json_encode($data, JSON_THROW_ON_ERROR));
        try {
            return AdvisoryCatalog::load($path);
        } finally {
            unlink($path);
        }
    }
}
