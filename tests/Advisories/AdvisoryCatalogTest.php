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

    /** @return iterable<string, array{string, string, array<string, string>, array<string, string>}> */
    public static function novemberAdvisories(): iterable
    {
        $all = ['8.2' => '8.2.36', '8.3' => '8.3.37', '8.4' => '8.4.28', '8.5' => '8.5.13'];
        yield 'CVE-2026-129289' => ['CVE-2026-129289', 'qc49-hpvq-g2w6', $all, ['nginx fastcgi_keep_conn / Apache mod_proxy_fcgi enablereuse' => 'blocks-described-vector']];
        yield 'CVE-2026-129496' => ['CVE-2026-129496', 'gr4f-wgx5-jpfv', $all, ['error_log' => 'partial']];
        yield 'CVE-2026-129474' => ['CVE-2026-129474', '8mjj-2r7p-4hg2', ['8.5' => '8.5.13'], ['zend.exception_ignore_args' => 'blocks-described-vector', 'fatal_error_backtraces' => 'blocks-described-vector']];
        // GHSA-2fjv offers fatal_error_backtraces=0 only as a temporary workaround, so it stays partial.
        yield 'CVE-2026-129182' => ['CVE-2026-129182', '2fjv-p558-g82m', ['8.5' => '8.5.13'], ['fatal_error_backtraces' => 'partial']];
        yield 'CVE-2026-129481' => ['CVE-2026-129481', 'g3vh-838c-65v7', ['8.3' => '8.3.37', '8.4' => '8.4.28', '8.5' => '8.5.13'], ['pm.max_requests' => 'partial']];
        yield 'CVE-2026-129291' => ['CVE-2026-129291', 'jm4m-qfqx-967m', $all, ['catch_workers_output' => 'blocks-described-vector']];
        yield 'CVE-2026-127960' => ['CVE-2026-127960', 'mmf9-xm3v-hg2x', $all, ['request_terminate_timeout' => 'partial']];
        yield 'CVE-2026-128064' => ['CVE-2026-128064', 'f6gg-rchx-xw8j', $all, []];
        yield 'CVE-2026-128090' => ['CVE-2026-128090', '68fq-fh7h-f8gr', $all, []];
        yield 'CVE-2026-15353' => ['CVE-2026-15353', 'q23r-hr55-xmpg', $all, []];
        yield 'CVE-2026-129506' => ['CVE-2026-129506', '4646-p932-gw34', $all, []];
        yield 'CVE-2026-129501' => ['CVE-2026-129501', 'x8r7-mg3g-74hg', ['8.4' => '8.4.28', '8.5' => '8.5.13'], []];
        yield 'CVE-2026-129438' => ['CVE-2026-129438', 'mg3p-mxj9-g2mm', ['8.5' => '8.5.13'], []];
        yield 'CVE-2026-129292' => ['CVE-2026-129292', '3mg3-cr28-46gc', $all, ['pm.status_path' => 'blocks-described-vector']];
        yield 'CVE-2026-129538' => ['CVE-2026-129538', '5j3f-64r7-f564', $all, ['cgi.fix_pathinfo' => 'blocks-described-vector']];
    }

    /**
     * @param array<string, string> $expectedFixed
     * @param array<string, string> $expectedMitigations setting => effect, exactly as the GHSA supports it
     */
    #[DataProvider('novemberAdvisories')]
    public function test_bundled_catalog_carries_the_verified_november_advisory(string $cve, string $ghsa, array $expectedFixed, array $expectedMitigations): void
    {
        $advisories = $this->byCve(AdvisoryCatalog::load());

        self::assertArrayHasKey($cve, $advisories);
        $advisory = $advisories[$cve];
        self::assertSame('https://github.com/php/php-src/security/advisories/GHSA-' . $ghsa, $advisory['source_url']);
        self::assertSame('2026-11-19', $advisory['revision']);
        // Exactly the branches the GHSA lists: no 8.6, no unfixed 8.1, branch-limited where stated.
        self::assertSame($expectedFixed, $advisory['fixed_upstream']);
        // Vendor backports must be sourced individually; none are encoded yet.
        self::assertSame([], $advisory['vendor_rules']);
        // Each mitigation is pinned: "blocks-described-vector" only where the GHSA says the setting removes the path.
        $mitigations = [];
        foreach ($advisory['mitigations'] as $mitigation) {
            self::assertSame($advisory['source_url'], $mitigation['source_url']);
            $mitigations[$mitigation['setting']] = $mitigation['effect'];
        }
        self::assertSame($expectedMitigations, $mitigations);
    }

    public function test_bundled_catalog_lists_every_2026_11_19_advisory_once(): void
    {
        $catalog = AdvisoryCatalog::load();
        $november = array_filter($catalog->advisories, static fn(array $advisory): bool => $advisory['revision'] === '2026-11-19');

        self::assertCount(17, $november);
        self::assertCount(19, $catalog->advisories);
        // One entry per CVE and one per GHSA: no advisory is listed twice under another id.
        self::assertCount(19, array_unique(array_column($catalog->advisories, 'cve')));
        self::assertCount(17, array_unique(array_column($november, 'source_url')));
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
