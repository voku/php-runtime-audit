<?php

declare(strict_types=1);

/**
 * Research-only local-file dpkg status probe.
 *
 * No shell commands, network requests, process discovery or patch verdicts.
 * This is NOT a production collector. No source contents or package version
 * are printed; the caller provides an independently observed comparison value.
 */
const MAX_DPKG_STATUS_BYTES = 8_388_608;
const TARGET_PACKAGE = 'php8.3-fpm';

/** @return non-empty-string */
function boundedRead(string $path): string
{
    if (is_link($path)) {
        throw new RuntimeException('Symlinked status path is refused.');
    }
    $before = @lstat($path);
    if (!is_array($before) || ($before['mode'] & 0170000) !== 0100000
        || $before['size'] < 1 || $before['size'] > MAX_DPKG_STATUS_BYTES) {
        throw new RuntimeException('Missing, oversized, or non-regular package database.');
    }
    $handle = @fopen($path, 'rb');
    if ($handle === false) {
        throw new RuntimeException('Cannot open the local package database.');
    }
    try {
        $opened = fstat($handle);
        if (!is_array($opened) || $opened['ino'] !== $before['ino']
            || $opened['dev'] !== $before['dev'] || $opened['size'] !== $before['size']) {
            throw new RuntimeException('Changed package database identity before reading.');
        }
        $data = stream_get_contents($handle, MAX_DPKG_STATUS_BYTES + 1);
        if (!is_string($data) || $data === '' || strlen($data) > MAX_DPKG_STATUS_BYTES
            || strlen($data) !== $opened['size']) {
            throw new RuntimeException('Incomplete or oversized package database read.');
        }
        $after = @lstat($path);
        if (!is_array($after) || $after['ino'] !== $opened['ino']
            || $after['dev'] !== $opened['dev'] || $after['size'] !== $opened['size']
            || $after['mtime'] !== $opened['mtime']) {
            throw new RuntimeException('Package database changed during observation.');
        }
        return $data;
    } finally {
        fclose($handle);
    }
}

/**
 * Narrow status-paragraph parser, not a full dpkg grammar implementation.
 *
 * @return array{version: string, installed: bool}|null
 */
function findExactPackage(string $data, string $package): ?array
{
    if ($data === '' || strlen($data) > MAX_DPKG_STATUS_BYTES || str_contains($data, "\0")) {
        throw new RuntimeException('Invalid package database content.');
    }
    $data = str_replace("\r\n", "\n", $data);
    $found = [];
    foreach (preg_split('/\n[ \t]*\n/', $data) ?: [] as $paragraph) {
        if ($paragraph === '') {
            continue;
        }
        $fields = [];
        $invalid = false;
        foreach (explode("\n", $paragraph) as $line) {
            if ($line === '') {
                continue;
            }
            if ($line[0] === ' ' || $line[0] === "\t") {
                continue; // Legitimate folded description field; never a new key.
            }
            if (preg_match('/\A([A-Za-z][A-Za-z0-9-]*):[ \t]+([^\r\n]*)\z/D', $line, $m) !== 1) {
                $invalid = true;
                continue;
            }
            if (in_array($m[1], ['Package', 'Version', 'Status'], true)) {
                $fields[$m[1]][] = $m[2];
            }
        }
        if (!in_array($package, $fields['Package'] ?? [], true)) {
            continue;
        }
        if ($invalid || count($fields['Package'] ?? []) !== 1
            || count($fields['Version'] ?? []) !== 1 || count($fields['Status'] ?? []) !== 1) {
            throw new RuntimeException('Malformed or conflicting target package record.');
        }
        $version = $fields['Version'][0];
        if (preg_match('/\A[0-9][a-zA-Z0-9.+:~_-]{0,127}\z/D', $version) !== 1) {
            throw new RuntimeException('Malformed package version.');
        }
        $found[] = ['version' => $version, 'installed' => $fields['Status'][0] === 'install ok installed'];
        if (count($found) > 1) {
            throw new RuntimeException('Duplicate target package records.');
        }
    }
    return $found[0] ?? null;
}

function selfTest(): void
{
    $valid = "Package: php8.3-fpm\nStatus: install ok installed\nArchitecture: amd64\nVersion: 8.3.6-0ubuntu0.24.04.13\nDescription: php-fpm\n extra folded description\n\n";
    $match = findExactPackage($valid, TARGET_PACKAGE);
    if ($match !== ['version' => '8.3.6-0ubuntu0.24.04.13', 'installed' => true]
        || findExactPackage($valid, 'not-a-package') !== null) {
        throw new RuntimeException('Valid/missing package tests failed.');
    }
    $bad = [
        $valid . $valid, // duplicate record
        str_replace("Version: 8.3.6-0ubuntu0.24.04.13\n", '', $valid),
        str_replace('Package: php8.3-fpm', "Package: php8.3-fpm\nPackage: php8.3-fpm", $valid),
        str_replace('Version: 8.3.6-0ubuntu0.24.04.13', 'Version: /invalid-path', $valid),
        str_replace("Description: php-fpm", "Invalid unparsed line", $valid),
        $valid . "\0",
    ];
    foreach ($bad as $index => $input) {
        try {
            findExactPackage($input, TARGET_PACKAGE);
        } catch (RuntimeException) {
            continue;
        }
        throw new RuntimeException('Malformed input accepted: case ' . $index);
    }

    $dir = sys_get_temp_dir() . '/pra-dpkg-' . bin2hex(random_bytes(8));
    if (!mkdir($dir, 0700) && !is_dir($dir)) {
        throw new RuntimeException('Could not create disposable test directory.');
    }
    try {
        $file = $dir . '/status';
        file_put_contents($file, $valid);
        if (boundedRead($file) !== $valid) {
            throw new RuntimeException('Bounded valid file test failed.');
        }
        $link = $dir . '/status-link';
        if (!symlink($file, $link)) {
            throw new RuntimeException('Symlink fixture unavailable.');
        }
        try {
            boundedRead($link);
            throw new LogicException('Symlinked database accepted.');
        } catch (RuntimeException) {
            // Expected rejection.
        }
        file_put_contents($file, str_repeat('x', MAX_DPKG_STATUS_BYTES + 1));
        try {
            boundedRead($file);
            throw new LogicException('Oversized database accepted.');
        } catch (RuntimeException) {
            // Expected rejection.
        }
    } finally {
        @unlink($dir . '/status-link');
        @unlink($dir . '/status');
        @rmdir($dir);
    }
}

$mode = $argv[1] ?? '';
if ($mode === '--self-test') {
    selfTest();
    echo "PASS: bounded dpkg status parser, duplicates, malformed input, symlink and oversized refusal\n";
    exit(0);
}
if ($mode !== '--host') {
    fwrite(STDERR, "Use --self-test or --host.\n");
    exit(2);
}
$expected = getenv('PRA_EXPECTED_DPKG_VERSION');
if (!is_string($expected) || $expected === '') {
    throw new RuntimeException('Missing independent dpkg-query control value in CI.');
}
$record = findExactPackage(boundedRead('/var/lib/dpkg/status'), TARGET_PACKAGE);
if ($record === null || !$record['installed'] || !hash_equals($expected, $record['version'])) {
    throw new RuntimeException('Bounded dpkg status parse disagrees with installed package control.');
}
echo json_encode([
    'schema_version' => 1,
    'experiment' => 'ci_only_bounded_local_dpkg_status_read',
    'target_package_present' => true,
    'target_package_installed' => true,
    'matched_external_package_manager_control' => true,
    'symlink_and_size_guards_tested' => true,
    'subprocess_or_network_execution_by_probe' => false,
    'trusted_vendor_signature_verified' => false,
    'loaded_worker_package_provenance_verified' => false,
    'patch_status' => 'unknown',
], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), "\n";
