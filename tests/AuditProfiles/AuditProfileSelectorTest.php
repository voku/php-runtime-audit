<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\AuditProfiles;

use InvalidArgumentException;
use LengthException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use voku\PhpRuntimeAudit\AuditProfiles\AuditFacts;
use voku\PhpRuntimeAudit\AuditProfiles\AuditIntent;
use voku\PhpRuntimeAudit\AuditProfiles\AuditProfileSelection;
use voku\PhpRuntimeAudit\AuditProfiles\AuditProfileSelector;
use voku\PhpRuntimeAudit\AuditProfiles\ProfileContextBuilder;
use voku\PhpRuntimeAudit\AuditProfiles\SelectedProfile;

final class AuditProfileSelectorTest extends TestCase
{
    public function test_debian_php_fpm_does_not_select_apache_or_unproven_container_guidance(): void
    {
        $facts = AuditFacts::fromArray([
            'php_version' => '8.3.12',
            'sapi' => 'fpm',
            'distribution' => 'debian',
            'vendor' => 'debian',
            'container' => null,
            'extensions' => ['json', 'opcache'],
            'configuration' => ['opcache.enable' => true],
        ]);

        $selection = (new AuditProfileSelector())->select(AuditIntent::RuntimePatch, $facts);
        $profileIds = $selection->profileIds();

        self::assertContains('runtime-patch', $profileIds);
        self::assertContains('sapi-php-fpm', $profileIds);
        self::assertContains('distribution-debian', $profileIds);
        self::assertContains('vendor-provenance', $profileIds);
        self::assertContains('php-extensions', $profileIds);
        self::assertContains('configuration-facts', $profileIds);
        self::assertContains('php-target-version', $profileIds);
        self::assertNotContains('sapi-apache-mod-php', $profileIds);
        self::assertNotContains('container', $profileIds);
        self::assertContains('container', $selection->unknownInputs());
        self::assertContains('vendor_backport_status', $selection->unknownInputs());
    }

    public function test_identical_facts_produce_stable_ordered_selection_and_unknown_inputs(): void
    {
        $facts = AuditFacts::fromArray([
            'sapi' => 'fpm',
            'container' => false,
            'distribution' => 'debian',
            'vendor' => 'debian',
            'extensions' => ['opcache', 'json'],
        ]);
        $selector = new AuditProfileSelector();

        $firstSelection = $selector->select(AuditIntent::Configuration, $facts);
        $secondSelection = $selector->select(AuditIntent::Configuration, $facts);
        $first = $firstSelection->toArray();
        $second = $secondSelection->toArray();
        $firstProfileIds = $firstSelection->profileIds();
        $firstUnknownInputs = $firstSelection->unknownInputs();
        $sortedProfileIds = $firstProfileIds;
        $sortedUnknownInputs = $firstUnknownInputs;
        sort($sortedProfileIds, SORT_STRING);
        sort($sortedUnknownInputs, SORT_STRING);

        self::assertSame($first, $second);
        self::assertSame($sortedProfileIds, $firstProfileIds);
        self::assertSame($sortedUnknownInputs, $firstUnknownInputs);
        self::assertSame($firstProfileIds, array_values(array_unique($firstProfileIds)));
        self::assertSame($firstUnknownInputs, array_values(array_unique($firstUnknownInputs)));
        self::assertNotContains('container', $firstProfileIds);
        self::assertNotContains('container', $firstUnknownInputs);
    }

    public function test_fact_loader_rejects_conflicting_multiple_sapi_values(): void
    {
        $this->expectException(InvalidArgumentException::class);
        AuditFacts::fromArray(['sapi' => ['fpm', 'apache2handler']]);
    }

    public function test_fact_loader_rejects_malformed_or_unsupported_fact_values(): void
    {
        foreach ([
            ['container' => 'sometimes'],
            ['configuration' => ['opcache.enable' => 'maybe']],
            ['unrecognized_fact' => true],
        ] as $facts) {
            $this->assertInvalidFacts($facts, 'Malformed or unsupported facts must be rejected.');
        }
    }

    public function test_fact_loader_rejects_string_encoded_applicability_values(): void
    {
        foreach (['true', 'false', 'unknown'] as $value) {
            foreach ([
                ['container' => $value],
                ['configuration' => ['opcache.enable' => $value]],
            ] as $facts) {
                $this->assertInvalidFacts($facts, 'Applicability facts must use typed boolean or null values.');
            }
        }
    }

    public function test_unsupported_sapi_remains_unknown_without_selecting_a_known_sapi_profile(): void
    {
        $selection = (new AuditProfileSelector())->select(
            AuditIntent::IncidentTriage,
            AuditFacts::fromArray(['sapi' => 'cgi-fcgi']),
        );

        self::assertNotContains('sapi-php-fpm', $selection->profileIds());
        self::assertNotContains('sapi-cli', $selection->profileIds());
        self::assertNotContains('sapi-apache-mod-php', $selection->profileIds());
        self::assertContains('sapi:unsupported', $selection->unknownInputs());
    }

    public function test_target_php_82_and_85_are_supported_with_php_82_project_requirement(): void
    {
        $selector = new AuditProfileSelector();

        foreach (['8.2.30', '8.5.1'] as $version) {
            $selection = $selector->select(
                AuditIntent::RuntimePatch,
                AuditFacts::fromArray(['php_version' => $version]),
            );

            self::assertContains('php-target-version', $selection->profileIds());
        }

        $unsupported = $selector->select(
            AuditIntent::RuntimePatch,
            AuditFacts::fromArray(['php_version' => '8.1.29']),
        );

        self::assertNotContains('php-target-version', $unsupported->profileIds());
        self::assertContains('php_version:unsupported', $unsupported->unknownInputs());

        $composerManifest = file_get_contents(dirname(__DIR__, 2) . '/composer.json');
        self::assertIsString($composerManifest);

        $manifest = json_decode(
            $composerManifest,
            true,
            512,
            JSON_THROW_ON_ERROR,
        );
        self::assertIsArray($manifest);
        self::assertIsArray($manifest['require'] ?? null);
        self::assertSame('^8.2', $manifest['require']['php'] ?? null);
    }

    public function test_unknown_vendor_backport_evidence_is_never_promoted_to_a_patch_verdict(): void
    {
        $selection = (new AuditProfileSelector())->select(
            AuditIntent::RuntimePatch,
            AuditFacts::fromArray(['distribution' => 'debian', 'vendor' => 'debian']),
        );
        $result = $selection->toArray();

        self::assertContains('vendor_backport_status', $selection->unknownInputs());
        self::assertArrayNotHasKey('patch_status', $result);
        self::assertArrayNotHasKey('compromise_evidence', $result);
        self::assertArrayNotHasKey('is_safe', $result);
    }

    public function test_each_supported_intent_selects_its_own_base_guidance(): void
    {
        $selector = new AuditProfileSelector();

        foreach (AuditIntent::cases() as $intent) {
            $selection = $selector->select($intent, AuditFacts::fromArray([]));

            self::assertContains($intent->value, $selection->profileIds());
        }
    }

    public function test_source_review_does_not_leak_runtime_specific_profiles_or_gaps(): void
    {
        $selection = (new AuditProfileSelector())->select(
            AuditIntent::SourceReview,
            AuditFacts::fromArray([
                'php_version' => '8.4.2',
                'sapi' => 'fpm',
                'distribution' => 'debian',
                'vendor' => 'debian',
                'container' => true,
                'extensions' => ['opcache'],
                'configuration' => ['opcache.enable' => true],
            ]),
        );

        self::assertSame(['php-target-version', 'source-review'], $selection->profileIds());
        self::assertSame([], $selection->unknownInputs());
    }

    public function test_context_builder_loads_only_selected_profiles_with_a_fixed_byte_budget(): void
    {
        $selection = (new AuditProfileSelector())->select(
            AuditIntent::RuntimePatch,
            AuditFacts::fromArray(['sapi' => 'fpm', 'container' => null]),
        );
        $context = (new ProfileContextBuilder())->load($selection);

        self::assertSame($selection->profileIds(), array_keys($context));
        self::assertArrayHasKey('sapi-php-fpm', $context);
        self::assertArrayNotHasKey('sapi-apache-mod-php', $context);
        self::assertArrayNotHasKey('container', $context);
        self::assertContains('container', $selection->unknownInputs());
        self::assertStringContainsString('PHP-FPM', $context['sapi-php-fpm']);
        self::assertLessThanOrEqual(ProfileContextBuilder::DEFAULT_MAX_BYTES, strlen(implode('', $context)));
    }

    public function test_context_builder_fails_closed_when_selected_guidance_exceeds_the_budget(): void
    {
        $selection = (new AuditProfileSelector())->select(
            AuditIntent::RuntimePatch,
            AuditFacts::fromArray([]),
        );

        $this->expectException(LengthException::class);
        (new ProfileContextBuilder(maximumBytes: 1))->load($selection);
    }

    public function test_context_builder_rejects_traversal_profile_identifiers(): void
    {
        $selection = new AuditProfileSelection(
            AuditIntent::SourceReview,
            [new SelectedProfile('../outside', 'Untrusted profile identifier.')],
            [],
        );

        $this->expectException(RuntimeException::class);
        (new ProfileContextBuilder())->load($selection);
    }

    public function test_context_builder_rejects_profiles_from_another_phar_archive(): void
    {
        $selection = (new AuditProfileSelector())->select(
            AuditIntent::RuntimePatch,
            AuditFacts::fromArray([]),
        );

        $this->expectException(RuntimeException::class);
        (new ProfileContextBuilder(
            'phar:///tmp/untrusted-runtime-audit.phar/resources/skills/php-runtime-audit/profiles',
        ))->load($selection);
    }

    public function test_context_builder_rejects_symlinked_profile_resources(): void
    {
        $temporaryRoot = sys_get_temp_dir() . '/php-runtime-audit-' . bin2hex(random_bytes(8));
        $profileRoot = $temporaryRoot . '/profiles';
        self::assertTrue(mkdir($profileRoot, 0700, true));

        $outsideProfile = $temporaryRoot . '/outside.md';
        $linkPath = $profileRoot . '/runtime-patch.md';
        file_put_contents($outsideProfile, 'This file is outside the profile directory.');
        if (!symlink($outsideProfile, $linkPath)) {
            unlink($outsideProfile);
            rmdir($profileRoot);
            rmdir($temporaryRoot);
            self::markTestSkipped('The current environment does not permit creating symlinks.');
        }

        $selection = (new AuditProfileSelector())->select(
            AuditIntent::RuntimePatch,
            AuditFacts::fromArray([]),
        );

        try {
            $this->expectException(RuntimeException::class);
            (new ProfileContextBuilder($profileRoot))->load($selection);
        } finally {
            unlink($linkPath);
            unlink($outsideProfile);
            rmdir($profileRoot);
            rmdir($temporaryRoot);
        }
    }

    public function test_cli_does_not_change_its_working_directory_or_fixture_files(): void
    {
        $workingDirectory = sys_get_temp_dir() . '/php-runtime-audit-' . bin2hex(random_bytes(8));
        self::assertTrue(mkdir($workingDirectory, 0700));
        $sentinelPath = $workingDirectory . '/sentinel.txt';
        file_put_contents($sentinelPath, 'unchanged');
        $beforeEntries = array_values(array_diff(scandir($workingDirectory) ?: [], ['.', '..']));
        $beforeSentinel = hash_file('sha256', $sentinelPath);

        try {
            $result = $this->runCli('{"intent":"source-review","facts":{}}', $workingDirectory);
            self::assertSame(0, $result['exit_code'], $result['stderr']);
            self::assertIsArray(json_decode($result['stdout'], true, 512, JSON_THROW_ON_ERROR));
            self::assertSame($beforeEntries, array_values(array_diff(scandir($workingDirectory) ?: [], ['.', '..'])));
            self::assertSame($beforeSentinel, hash_file('sha256', $sentinelPath));
        } finally {
            unlink($sentinelPath);
            rmdir($workingDirectory);
        }
    }

    public function test_cli_rejects_duplicate_json_facts_instead_of_overriding_evidence(): void
    {
        $root = dirname(__DIR__, 2);
        $result = $this->runCli('{"intent":"runtime-patch","facts":{"container":true,"\u0063ontainer":false}}', $root);

        self::assertSame(2, $result['exit_code']);
        self::assertSame('', $result['stdout']);
        self::assertStringContainsString('Duplicate keys in JSON objects', $result['stderr']);
    }

    public function test_cli_rejects_a_non_object_fact_set(): void
    {
        $result = $this->runCli('{"intent":"runtime-patch","facts":null}', dirname(__DIR__, 2));

        self::assertSame(2, $result['exit_code']);
        self::assertStringContainsString('Input facts must be a JSON object.', $result['stderr']);
    }

    public function test_cli_rejects_a_configuration_array(): void
    {
        $result = $this->runCli(
            '{"intent":"runtime-patch","facts":{"configuration":[]}}',
            dirname(__DIR__, 2),
        );

        self::assertSame(2, $result['exit_code']);
        self::assertSame('', $result['stdout']);
        self::assertStringContainsString('Input configuration must be a JSON object or null.', $result['stderr']);
    }

    public function test_cli_rejects_a_quoted_boolean_instead_of_selecting_a_profile(): void
    {
        $result = $this->runCli(
            '{"intent":"runtime-patch","facts":{"container":"true"}}',
            dirname(__DIR__, 2),
        );

        self::assertSame(2, $result['exit_code']);
        self::assertSame('', $result['stdout']);
        self::assertStringContainsString('must be true, false, or unknown', $result['stderr']);
    }

    public function test_cli_accepts_an_empty_configuration_object_as_unknown(): void
    {
        $result = $this->runCli(
            '{"intent":"runtime-patch","facts":{"configuration":{}}}',
            dirname(__DIR__, 2),
        );

        self::assertSame(0, $result['exit_code'], $result['stderr']);
        $payload = json_decode($result['stdout'], true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($payload);
        self::assertIsArray($payload['unknown_inputs'] ?? null);
        self::assertContains('configuration', $payload['unknown_inputs']);
    }

    /** @param array<string, mixed> $facts */
    private function assertInvalidFacts(array $facts, string $message): void
    {
        try {
            AuditFacts::fromArray($facts);
        } catch (InvalidArgumentException $exception) {
            self::assertNotSame('', $exception->getMessage(), $message);
            return;
        }

        self::fail($message);
    }

    /** @return array{exit_code: int, stdout: string, stderr: string} */
    private function runCli(string $input, string $workingDirectory): array
    {
        $scriptPath = dirname(__DIR__, 2) . '/bin/php-runtime-audit';
        $process = proc_open(
            [PHP_BINARY, $scriptPath],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            $workingDirectory,
        );
        if (!is_resource($process)) {
            throw new RuntimeException('Unable to start the PHP audit CLI for a test.');
        }

        try {
            fwrite($pipes[0], $input);
            fclose($pipes[0]);
            $stdout = stream_get_contents($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $exitCode = proc_close($process);
            $process = null;

            return [
                'exit_code' => $exitCode,
                'stdout' => (string) $stdout,
                'stderr' => (string) $stderr,
            ];
        } finally {
            if (is_resource($process)) {
                proc_terminate($process);
                foreach ($pipes as $pipe) {
                    if (is_resource($pipe)) {
                        fclose($pipe);
                    }
                }
                proc_close($process);
            }
        }
    }
}
