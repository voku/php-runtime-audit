<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\RuntimeInventory;

use PHPUnit\Framework\TestCase;
use voku\PhpRuntimeAudit\RuntimeInventory\NetworkIsolation;
use voku\PhpRuntimeAudit\RuntimeInventory\ProcessCommand;
use voku\PhpRuntimeAudit\RuntimeInventory\SystemProcessRunner;

final class NetworkIsolationTest extends TestCase
{
    private const DEVICES = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
    private const STATUS = "Name:\tphp\nNoNewPrivs:\t1\nCapInh:\t0000000000000000\nCapPrm:\t00000000a00425fb\nCapEff:\t00000000a00425fb\nCapBnd:\t00000000a00425fb\nCapAmb:\t0000000000000000\n";

    public function test_only_complete_kernel_observations_establish_existing_isolation(): void
    {
        self::assertTrue(NetworkIsolation::observationsProveIsolation(self::DEVICES, self::STATUS));
        foreach ([null, '', "lo: 0\n", self::DEVICES . "eth0: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", self::DEVICES . "    lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"] as $devices) {
            self::assertFalse(NetworkIsolation::observationsProveIsolation($devices, self::STATUS));
        }
        foreach ([null, '', str_replace("NoNewPrivs:\t1", "NoNewPrivs:\t0", self::STATUS), self::STATUS . "NoNewPrivs:\t1\n", str_replace('a00425fb', 'ffffffffffffffff', self::STATUS), str_replace('a00425fb', str_repeat('f', 500), self::STATUS), str_replace('a00425fb', '0000000000200000', self::STATUS), str_replace('a00425fb', '0000000000001000', self::STATUS)] as $status) {
            self::assertFalse(NetworkIsolation::observationsProveIsolation(self::DEVICES, $status));
        }
    }

    public function test_every_capability_set_and_missing_status_field_fail_closed(): void
    {
        foreach (['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'] as $name) {
            $withAdmin = preg_replace('/^' . $name . ':.*$/m', $name . ":\t0000000000201000", self::STATUS);
            self::assertIsString($withAdmin);
            self::assertFalse(NetworkIsolation::observationsProveIsolation(self::DEVICES, $withAdmin));
            $missing = preg_replace('/^' . $name . ':.*\n/m', '', self::STATUS);
            self::assertIsString($missing);
            self::assertFalse(NetworkIsolation::observationsProveIsolation(self::DEVICES, $missing));
        }
        self::assertFalse(NetworkIsolation::observationsProveIsolation(str_repeat('x', 65537), self::STATUS));
        self::assertFalse(NetworkIsolation::observationsProveIsolation(self::DEVICES, str_repeat('x', 65537)));
    }

    public function test_public_runner_uses_kernel_boundary_or_reports_failure_without_facts(): void
    {
        $command = is_executable('/usr/local/bin/php') ? ProcessCommand::PhpUsrLocalBin : ProcessCommand::PhpUsrBin;
        $result = (new SystemProcessRunner())->run($command);
        if (!is_executable($command->executablePath())) {
            self::assertFalse($result->succeeded());
            self::assertSame('', $result->stdout);
            self::assertSame('allowlisted executable is unavailable', $result->error);

            return;
        }

        if (NetworkIsolation::currentNamespaceIsIsolated()) {
            self::assertTrue($result->succeeded(), $result->stderr . ($result->error ?? ''));
            $this->assertPhpPayload($result->stdout);
        } elseif (!$result->succeeded()) {
            self::assertSame('', $result->stdout);
            self::assertNotNull($result->error);
            self::assertStringContainsString('network isolation', $result->error);
        } else {
            $this->assertPhpPayload($result->stdout);
        }
    }

    private function assertPhpPayload(string $stdout): void
    {
        $payload = json_decode($stdout, true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($payload);
        self::assertSame('cli', $payload['sapi']);
    }
}
