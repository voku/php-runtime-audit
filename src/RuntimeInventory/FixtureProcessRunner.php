<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\RuntimeInventory;

use InvalidArgumentException;
use RuntimeException;
use voku\PhpRuntimeAudit\Evidence\DuplicateJsonKeyGuard;

/** Reads canned command results from an offline fixture; never starts a process. */
final class FixtureProcessRunner implements ProcessRunner
{
    /** @var array<string, mixed> */
    private array $results;

    public function __construct(string $fixtureRoot)
    {
        $root = realpath($fixtureRoot);
        $path = is_string($root) ? $root . '/commands.json' : '';
        if ($root === false || !is_dir($root) || !is_file($path) || is_link($path)) {
            throw new RuntimeException('Fixture root must contain a regular commands.json file.');
        }
        $size = filesize($path);
        if (!is_int($size) || $size > 262_144) {
            throw new RuntimeException('Fixture command data is unreadable or too large.');
        }
        $json = file_get_contents($path, false, null, 0, 262_145);
        if (!is_string($json) || strlen($json) > 262_144) {
            throw new RuntimeException('Fixture command data is unreadable or too large.');
        }
        DuplicateJsonKeyGuard::assertNoDuplicates($json);
        $data = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
        if (!is_array($data) || array_diff(array_keys($data), ['commands']) !== [] || !is_array($data['commands'] ?? null)) {
            throw new InvalidArgumentException('Fixture command data must contain only a commands object.');
        }
        $allowedCommands = array_map(static fn(ProcessCommand $command): string => $command->value, ProcessCommand::cases());
        $results = [];
        foreach ($data['commands'] as $name => $result) {
            if (!is_string($name) || !in_array($name, $allowedCommands, true) || !is_array($result)) {
                throw new InvalidArgumentException('Fixture commands must name only allowlisted commands with object results.');
            }
            $results[$name] = $result;
        }
        $this->results = $results;
    }

    public function run(ProcessCommand $command): ProcessResult
    {
        $result = $this->results[$command->value] ?? null;
        if (!is_array($result)
            || array_diff(array_keys($result), ['exit_code', 'stdout', 'stderr', 'timed_out', 'truncated', 'error']) !== []
            || !is_string($result['stdout'] ?? null)) {
            return new ProcessResult(null, '', error: 'fixture command result is missing or malformed');
        }
        $exitCode = $result['exit_code'] ?? null;
        $stderr = $result['stderr'] ?? '';
        $timedOut = $result['timed_out'] ?? false;
        $truncated = $result['truncated'] ?? false;
        $error = $result['error'] ?? null;
        if (($exitCode !== null && !is_int($exitCode))
            || !is_string($stderr)
            || !is_bool($timedOut)
            || !is_bool($truncated)
            || ($error !== null && !is_string($error))) {
            return new ProcessResult(null, '', error: 'fixture command result has invalid field types');
        }

        return new ProcessResult(
            $exitCode,
            substr($result['stdout'], 0, $command->outputLimitBytes()),
            substr($stderr, 0, $command->outputLimitBytes()),
            $timedOut,
            $truncated || strlen($result['stdout']) > $command->outputLimitBytes() || strlen($stderr) > $command->outputLimitBytes(),
            $error,
        );
    }
}
