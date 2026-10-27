<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\Remediation;

use PHPUnit\Framework\TestCase;

final class RemediationReportCliTest extends TestCase
{
    public function test_full_pipeline_from_inventory_fixture_to_remediation_plan_and_report_md(): void
    {
        $root = dirname(__DIR__, 2);
        $reportPath = sys_get_temp_dir() . '/pra5-report-' . bin2hex(random_bytes(8)) . '.md';

        $inventoryJson = $this->runCli([PHP_BINARY, $root . '/bin/php-runtime-audit-inventory', '--fixture', $root . '/tests/fixtures/runtime/debian-fpm-vulnerable'], '');
        self::assertNotSame('', $inventoryJson['stdout']);

        try {
            $result = $this->runCli([PHP_BINARY, $root . '/bin/php-runtime-audit-report', '--report', $reportPath], $inventoryJson['stdout']);

            self::assertSame(0, $result['exit'], $result['stderr']);
            $plan = json_decode($result['stdout'], true, 512, JSON_THROW_ON_ERROR);
            self::assertSame('remediation_plan', $plan['record_type']);
            self::assertFalse($plan['automatic_apply']);
            self::assertNotEmpty($plan['actions']);
            foreach ($plan['actions'] as $action) {
                self::assertTrue($action['requires_human_approval']);
            }

            self::assertFileExists($reportPath);
            $markdown = (string) file_get_contents($reportPath);
            self::assertStringContainsString('remediation report', $markdown);
            self::assertStringContainsString('**WHY**', $markdown);
            self::assertStringContainsString('**ROLLBACK**', $markdown);
        } finally {
            @unlink($reportPath);
        }
    }

    public function test_oversized_stdin_is_rejected(): void
    {
        $root = dirname(__DIR__, 2);
        $result = $this->runCli([PHP_BINARY, $root . '/bin/php-runtime-audit-report'], str_repeat('a', 1_048_577));

        self::assertSame(2, $result['exit']);
        self::assertStringContainsString('must be a non-empty runtime audit report', $result['stderr']);
    }

    public function test_duplicate_json_keys_are_rejected(): void
    {
        $root = dirname(__DIR__, 2);
        $result = $this->runCli([PHP_BINARY, $root . '/bin/php-runtime-audit-report'], '{"records": [], "records": []}');

        self::assertSame(2, $result['exit']);
        self::assertStringContainsString('duplicate', $result['stderr']);
    }

    public function test_non_object_json_is_rejected(): void
    {
        $root = dirname(__DIR__, 2);
        $result = $this->runCli([PHP_BINARY, $root . '/bin/php-runtime-audit-report'], '"just a string"');

        self::assertSame(2, $result['exit']);
    }

    public function test_report_flag_refuses_a_symlinked_destination(): void
    {
        $root = dirname(__DIR__, 2);
        $target = sys_get_temp_dir() . '/pra5-symlink-target-' . bin2hex(random_bytes(8));
        $link = sys_get_temp_dir() . '/pra5-symlink-' . bin2hex(random_bytes(8)) . '.md';
        file_put_contents($target, 'pre-existing');
        self::assertTrue(symlink($target, $link));

        try {
            $result = $this->runCli([PHP_BINARY, $root . '/bin/php-runtime-audit-report', '--report', $link], '{"records": []}');

            self::assertSame(2, $result['exit']);
            self::assertStringContainsString('symlink', $result['stderr']);
            self::assertSame('pre-existing', (string) file_get_contents($target), 'A symlinked destination must never be written through.');
        } finally {
            @unlink($link);
            @unlink($target);
        }
    }

    public function test_help_flag_prints_usage_without_reading_stdin(): void
    {
        $root = dirname(__DIR__, 2);
        $result = $this->runCli([PHP_BINARY, $root . '/bin/php-runtime-audit-report', '--help'], '');

        self::assertSame(0, $result['exit']);
        self::assertStringContainsString('Usage:', $result['stdout']);
    }

    public function test_report_with_no_usable_records_produces_an_empty_plan_not_a_crash(): void
    {
        $root = dirname(__DIR__, 2);
        $result = $this->runCli([PHP_BINARY, $root . '/bin/php-runtime-audit-report'], '{"summary": {}}');

        self::assertSame(0, $result['exit'], $result['stderr']);
        $plan = json_decode($result['stdout'], true, 512, JSON_THROW_ON_ERROR);
        self::assertSame([], $plan['actions']);
        self::assertNotEmpty($plan['warnings']);
    }

    /**
     * @param list<string> $command
     * @return array{stdout: string, stderr: string, exit: int}
     */
    private function runCli(array $command, string $stdin): array
    {
        $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, dirname(__DIR__, 2));
        self::assertIsResource($process);
        fwrite($pipes[0], $stdin);
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exit = proc_close($process);

        self::assertIsString($stdout);
        self::assertIsString($stderr);

        return ['stdout' => $stdout, 'stderr' => $stderr, 'exit' => $exit];
    }
}
