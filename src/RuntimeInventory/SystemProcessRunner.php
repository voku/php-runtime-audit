<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\RuntimeInventory;

use Throwable;

/** Executes only allowlisted commands with bounded time/output and kernel network isolation. */
final class SystemProcessRunner implements ProcessRunner
{
    public function run(ProcessCommandSpec $command): ProcessResult
    {
        if (!$command instanceof ProcessCommand && !$command instanceof DiscoveredPhpCommand) {
            return new ProcessResult(null, '', error: 'process request is outside the bounded execution policy');
        }

        $argv = $command->argv();
        if (($argv[0] ?? null) !== $command->executablePath()) {
            return new ProcessResult(null, '', error: 'process request is outside the bounded execution policy');
        }

        $executablePath = $command->executablePath();
        if ($command instanceof DiscoveredPhpCommand) {
            $resolvedExecutablePath = $command->resolvedExecutablePath();
        } elseif ($command->isPhpCli() || $command->isFpm()) {
            $resolvedExecutablePath = DiscoveredPhpCommand::resolveAllowedExecutableTarget(
                $executablePath,
                $command->isFpm() ? 'fpm' : 'cli',
            );
        } else {
            $resolvedExecutablePath = self::resolveAllowlistedExecutable(
                $executablePath,
                self::allowedCanonicalExecutablePaths($command),
            );
            if ($resolvedExecutablePath === null) {
                return new ProcessResult(null, '', error: 'process request is outside the bounded execution policy');
            }
        }
        if ($resolvedExecutablePath === null || !is_executable($resolvedExecutablePath)) {
            return new ProcessResult(null, '', error: 'allowlisted executable is unavailable');
        }
        $argv[0] = $resolvedExecutablePath;

        if (NetworkIsolation::currentNamespaceIsIsolated()) {
            return $this->execute($argv, $command->timeoutSeconds(), $command->outputLimitBytes());
        }

        // Fixed util-linux tools create a fresh network namespace with no external interfaces.
        // NoNewPrivs is inherited across unshare/exec; user namespaces need no host privilege.
        if (!is_executable('/usr/bin/setpriv') || !is_executable('/usr/bin/unshare')) {
            return new ProcessResult(null, '', error: 'network isolation is unavailable; command was not executed');
        }
        $isolated = ['/usr/bin/setpriv', '--no-new-privs', '/usr/bin/unshare', '--user', '--map-root-user', '--net', '--', ...$argv];
        $result = $this->execute($isolated, $command->timeoutSeconds(), $command->outputLimitBytes());
        if (!$result->succeeded()) {
            // Never expose partial facts when the boundary could not be established or execution failed.
            return new ProcessResult(
                $result->exitCode,
                '',
                $result->stderr,
                $result->timedOut,
                $result->truncated,
                'network isolation or isolated command failed; facts are unavailable',
            );
        }

        return $result;
    }

    /** @return list<string> */
    private static function allowedCanonicalExecutablePaths(ProcessCommand $command): array
    {
        return match ($command) {
            ProcessCommand::ApkPackages => ['/sbin/apk', '/usr/sbin/apk'],
            default => [$command->executablePath()],
        };
    }

    /**
     * @param list<string> $allowedCanonicalPaths
     */
    private static function resolveAllowlistedExecutable(string $executablePath, array $allowedCanonicalPaths): ?string
    {
        if (is_link($executablePath)) {
            return null;
        }

        $resolvedExecutablePath = realpath($executablePath);
        if (!is_string($resolvedExecutablePath) || !in_array($resolvedExecutablePath, $allowedCanonicalPaths, true)) {
            return null;
        }

        return $resolvedExecutablePath;
    }

    /** @param list<string> $argv */
    private function execute(array $argv, float $timeoutSeconds, int $outputLimitBytes): ProcessResult
    {
        if ($argv === [] || count($argv) > 16
            || !str_starts_with($argv[0], '/') || !is_executable($argv[0])
            || $timeoutSeconds <= 0 || $timeoutSeconds > 10
            || $outputLimitBytes < 1 || $outputLimitBytes > 1_048_576) {
            return new ProcessResult(null, '', error: 'process request is outside the bounded execution policy');
        }
        foreach ($argv as $argument) {
            if (strlen($argument) > 4096 || preg_match('/[\x00-\x1F\x7F]/', $argument) === 1) {
                return new ProcessResult(null, '', error: 'process arguments are malformed');
            }
        }

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        try {
            $process = proc_open(
                $argv,
                $descriptors,
                $pipes,
                '/',
                ['LC_ALL' => 'C', 'PATH' => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'],
                ['bypass_shell' => true],
            );
        } catch (Throwable) {
            return new ProcessResult(null, '', error: 'allowlisted command could not be started');
        }

        if (!is_resource($process)) {
            return new ProcessResult(null, '', error: 'allowlisted command could not be started');
        }

        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $stdout = '';
        $stderr = '';
        $startedAt = microtime(true);
        $timedOut = false;
        $truncated = false;
        $exitCode = null;

        while (true) {
            $read = [];
            if (!feof($pipes[1])) {
                $read[] = $pipes[1];
            }
            if (!feof($pipes[2])) {
                $read[] = $pipes[2];
            }
            if ($read !== []) {
                $write = null;
                $except = null;
                @stream_select($read, $write, $except, 0, 100_000);
                foreach ($read as $stream) {
                    $chunk = fread($stream, 8192);
                    if (!is_string($chunk) || $chunk === '') {
                        continue;
                    }
                    if ($stream === $pipes[1]) {
                        $stdout .= $chunk;
                    } else {
                        $stderr .= $chunk;
                    }
                }
            }

            if (strlen($stdout) + strlen($stderr) > $outputLimitBytes) {
                $truncated = true;
                proc_terminate($process, 9);
                break;
            }

            $status = proc_get_status($process);
            if (!$status['running']) {
                $exitCode = $status['exitcode'] >= 0 ? $status['exitcode'] : null;
                // A child can exit after writing more than one pipe buffer. Drain only until
                // the cap, so completed processes cannot bypass truncation detection.
                while (true) {
                    $remaining = [];
                    foreach ([1, 2] as $index) {
                        if (isset($pipes[$index]) && is_resource($pipes[$index]) && !feof($pipes[$index])) {
                            $remaining[$index] = $pipes[$index];
                        }
                    }
                    if (count($remaining) === 0) {
                        break;
                    }
                    $write = null;
                    $except = null;
                    $selectedStreams = @stream_select($remaining, $write, $except, 0, 100_000);
                    if ($selectedStreams === false || $selectedStreams === 0) {
                        break;
                    }
                    foreach ($remaining as $index => $stream) {
                        $chunk = fread($stream, 8192);
                        if (!is_string($chunk) || $chunk === '') {
                            continue;
                        }
                        if ($index === 1) {
                            $stdout .= $chunk;
                        } else {
                            $stderr .= $chunk;
                        }
                    }
                    if (strlen($stdout) + strlen($stderr) > $outputLimitBytes) {
                        $truncated = true;
                        break;
                    }
                }
                break;
            }
            if (microtime(true) - $startedAt > $timeoutSeconds) {
                $timedOut = true;
                proc_terminate($process, 9);
                break;
            }
        }

        foreach ([1, 2] as $index) {
            if (isset($pipes[$index]) && is_resource($pipes[$index])) {
                fclose($pipes[$index]);
            }
        }
        $closedCode = proc_close($process);
        if ($exitCode === null && $closedCode >= 0) {
            $exitCode = $closedCode;
        }

        return new ProcessResult(
            $exitCode,
            substr($stdout, 0, $outputLimitBytes),
            substr($stderr, 0, $outputLimitBytes),
            $timedOut,
            $truncated,
        );
    }
}
