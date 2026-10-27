<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\RuntimeInventory;

/** Kernel observations are always read from the running host, never a fixture root. */
final class NetworkIsolation
{
    public static function currentNamespaceIsIsolated(): bool
    {
        return self::observationsProveIsolation(self::read('/proc/net/dev'), self::read('/proc/self/status'));
    }

    public static function observationsProveIsolation(?string $devices, ?string $status): bool
    {
        if ($devices === null || $status === null || strlen($devices) > 65536 || strlen($status) > 65536) {
            return false;
        }
        $lines = explode("\n", trim($devices));
        if (count($lines) !== 3
            || preg_match('/^Inter-\|\s+Receive\s+\|\s+Transmit$/D', trim($lines[0])) !== 1
            || preg_match('/^face\s+\|bytes\s+packets errs drop fifo frame compressed multicast\|bytes\s+packets errs drop fifo colls carrier compressed$/D', trim($lines[1])) !== 1
            || preg_match('/^lo:(?:\s+[0-9]+){16}$/D', trim($lines[2])) !== 1) {
            return false;
        }

        $required = ['NoNewPrivs', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'];
        $values = [];
        foreach (explode("\n", $status) as $line) {
            $parts = explode(':', $line, 2);
            if (!in_array($parts[0], $required, true)) {
                continue;
            }
            if (count($parts) !== 2 || isset($values[$parts[0]])) {
                return false;
            }
            $values[$parts[0]] = trim($parts[1]);
        }
        if (count($values) !== count($required) || ($values['NoNewPrivs'] ?? null) !== '1') {
            return false;
        }
        foreach (array_slice($required, 1) as $name) {
            $hex = $values[$name] ?? '';
            if (preg_match('/^[0-9a-fA-F]{16}$/D', $hex) !== 1) {
                return false;
            }
            // Inspect one nibble at a time: malformed/oversized masks never enter integer conversion.
            foreach ([12, 21] as $bit) { // CAP_NET_ADMIN, CAP_SYS_ADMIN
                $nibble = hexdec($hex[15 - intdiv($bit, 4)]);
                if (((int) $nibble & (1 << ($bit % 4))) !== 0) {
                    return false;
                }
            }
        }

        return true;
    }

    private static function read(string $path): ?string
    {
        $contents = @file_get_contents($path, false, null, 0, 65537);

        return is_string($contents) && strlen($contents) <= 65536 ? $contents : null;
    }
}
