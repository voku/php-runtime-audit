<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\RuntimeInventory;

/**
 * Checks consistency with the local dpkg database, not independently signed vendor authenticity.
 * MD5 is dpkg's installed-file integrity format; SHA-256 and inode checks bind the loaded file.
 * A privileged attacker who changes both the binary and package database is outside this proof.
 *
 * @phpstan-type PackageProvenance array{verified: bool, package_name: string|null, package_version: string|null, executable_path: string|null, method: string|null, reason: string, trust_boundary: 'local_package_database', evidence_source_ids: list<string>}
 * @phpstan-type ProvenanceSource array{locator: string, content: string|null}
 * @phpstan-type FileFingerprint array{md5: string, sha256: string, dev: int, ino: int, size: int}
 */
final class RuntimePackageProvenance
{
    private const MAX_BINARY_BYTES = 33_554_432;
    private const MAX_METADATA_BYTES = 1_048_576;
    private int $remainingHashBytes = 67_108_864;
    private bool $statusCaptured = false;
    private ?string $capturedStatus = null;
    /** @var array<string, array{provenance: PackageProvenance, sources: list<ProvenanceSource>}> */
    private array $apacheModuleCache = [];

    public function __construct(private readonly string $root) {}

    /** @return PackageProvenance */
    public static function unknown(string $reason): array
    {
        return [
            'verified' => false,
            'package_name' => null,
            'package_version' => null,
            'executable_path' => null,
            'method' => null,
            'reason' => $reason,
            'trust_boundary' => 'local_package_database',
            'evidence_source_ids' => [],
        ];
    }

    /**
     * @param list<array{name: string, version: string}> $packages
     * @return array{provenance: PackageProvenance, sources: list<ProvenanceSource>}
     */
    public function check(?string $distribution, ?string $manager, array $packages, ?string $path, string $procBase): array
    {
        $unknown = static fn(string $reason): array => ['provenance' => self::unknown($reason), 'sources' => []];
        if (!in_array($distribution, ['debian', 'ubuntu'], true) || $manager !== 'dpkg') {
            return $unknown('unsupported_package_integrity');
        }
        if ($path === null || preg_match('~\A/usr/sbin/php-fpm([0-9]+\.[0-9]{1,2})\z~', $path, $match) !== 1) {
            return $unknown('unsupported_executable_path');
        }
        $name = 'php' . $match[1] . '-fpm';
        $matching = array_values(array_filter($packages, static fn(array $package): bool => $package['name'] === $name));
        if (count($matching) !== 1) {
            return $unknown('package_identity_unavailable');
        }
        $version = $matching[0]['version'];
        if (!$this->statusCaptured) {
            $this->capturedStatus = $this->readMetadata('/var/lib/dpkg/status', 8_388_608);
            $this->statusCaptured = true;
        }
        $status = $this->capturedStatus;
        if ($status === null) {
            return $unknown('package_status_unavailable');
        }
        $stanzas = [];
        foreach (preg_split('/\n\s*\n/', $status) ?: [] as $stanza) {
            $fields = [];
            $duplicate = false;
            foreach (explode("\n", $stanza) as $line) {
                if (preg_match('/\A(Package|Version|Status|Architecture): (.*)\z/', $line, $field) === 1) {
                    $duplicate = $duplicate || isset($fields[$field[1]]);
                    $fields[$field[1]] = $field[2];
                }
            }
            if (($fields['Package'] ?? null) === $name) {
                if ($duplicate) {
                    return $unknown('package_status_ambiguous');
                }
                $stanzas[] = $fields;
            }
        }
        if (count($stanzas) !== 1 || ($stanzas[0]['Version'] ?? null) !== $version
            || !DpkgPackageStatus::hasVerifiedIntegrityStatus($stanzas[0]['Status'] ?? '')) {
            return $unknown('package_status_mismatch');
        }
        $metadataPaths = ['/var/lib/dpkg/info/' . $name . '.md5sums'];
        $architecture = $stanzas[0]['Architecture'] ?? '';
        if (preg_match('/\A[a-z0-9-]{1,32}\z/', $architecture) === 1) {
            $metadataPaths[] = '/var/lib/dpkg/info/' . $name . ':' . $architecture . '.md5sums';
        }
        $checksums = [];
        foreach ($metadataPaths as $metadataPath) {
            if (file_exists($this->rootPath($metadataPath)) || is_link($this->rootPath($metadataPath))) {
                $checksums[$metadataPath] = $this->readMetadata($metadataPath);
            }
        }
        if (count($checksums) !== 1 || ($contents = array_values($checksums)[0]) === null || !str_ends_with($contents, "\n")) {
            return $unknown('package_checksums_unavailable');
        }
        $expected = [];
        foreach (explode("\n", rtrim($contents, "\n")) as $line) {
            if (preg_match('/\A([a-f0-9]{32})  ([^\x00-\x1F\x7F]{1,512})\z/', $line, $entry) !== 1) {
                return $unknown('package_checksums_malformed');
            }
            if ($entry[2] === ltrim($path, '/')) {
                $expected[] = $entry[1];
            }
        }
        if (count($expected) !== 1) {
            return $unknown('package_ownership_ambiguous');
        }
        if (!$this->safeRegularPath($path) || !$this->safeRegularPath($procBase, true)
            || !is_link($this->rootPath($procBase . '/exe'))) {
            return $unknown('executable_identity_unavailable');
        }
        $installed = $this->fingerprint($this->rootPath($path));
        $loaded = $this->fingerprint($this->rootPath($procBase . '/exe'));
        $sources = [
            ['locator' => '/var/lib/dpkg/status', 'content' => $status],
            ['locator' => (string) array_key_first($checksums), 'content' => $contents],
            ['locator' => $path . ':fingerprint', 'content' => $installed === null ? null : json_encode($installed, JSON_THROW_ON_ERROR)],
            ['locator' => $procBase . '/exe:fingerprint', 'content' => $loaded === null ? null : json_encode($loaded, JSON_THROW_ON_ERROR)],
        ];
        $proof = self::unknown('binary_integrity_unavailable');
        if ($installed !== null && $loaded !== null && $installed === $loaded && $installed['md5'] === $expected[0]) {
            $proof = [
                'verified' => true,
                'package_name' => $name,
                'package_version' => $version,
                'executable_path' => $path,
                'method' => 'dpkg_md5sums_loaded_executable',
                'reason' => 'local_package_integrity_matched',
                'trust_boundary' => 'local_package_database',
                'evidence_source_ids' => [],
            ];
        }

        return ['provenance' => $proof, 'sources' => $sources];
    }

    /**
     * Reverse lookup for Apache PHP modules: unlike php-fpm binaries, the loaded module's
     * filename does not reliably encode its version (modern builds ship an unversioned
     * `libphp.so`). Instead of guessing the owning package from the filename, every installed
     * `libapache2-mod-php*` package's own md5sums manifest is checked for a claim on this exact
     * path; verification only succeeds when exactly one installed package claims it and the
     * on-disk file matches that claim.
     *
     * @param list<array{name: string, version: string}> $packages
     * @return array{provenance: PackageProvenance, sources: list<ProvenanceSource>}
     */
    public function checkApacheModule(?string $distribution, ?string $manager, array $packages, ?string $path, ?bool $moduleDeleted): array
    {
        $unknown = static fn(string $reason): array => ['provenance' => self::unknown($reason), 'sources' => []];
        if (!in_array($distribution, ['debian', 'ubuntu'], true) || $manager !== 'dpkg') {
            return $unknown('unsupported_package_integrity');
        }
        if ($moduleDeleted !== false || $path === null || preg_match('~\A/[^\x00-\x1F]*/libphp[^\x00-\x1F/]*\.so\z~', $path) !== 1) {
            return $unknown('unsupported_executable_path');
        }
        // Multiple Apache worker processes commonly map the same shared module file; cache the
        // resolved identity per path so their redundant provenance checks don't re-walk dpkg's
        // metadata and re-hash the same file against the shared hashing budget each time.
        return $this->apacheModuleCache[$path] ??= $this->resolveApacheModuleOwner($packages, $path);
    }

    /**
     * @param list<array{name: string, version: string}> $packages
     * @return array{provenance: PackageProvenance, sources: list<ProvenanceSource>}
     */
    private function resolveApacheModuleOwner(array $packages, string $path): array
    {
        $unknown = static fn(string $reason): array => ['provenance' => self::unknown($reason), 'sources' => []];
        if (!$this->statusCaptured) {
            $this->capturedStatus = $this->readMetadata('/var/lib/dpkg/status', 8_388_608);
            $this->statusCaptured = true;
        }
        $status = $this->capturedStatus;
        if ($status === null) {
            return $unknown('package_status_unavailable');
        }
        $candidates = [];
        foreach (preg_split('/\n\s*\n/', $status) ?: [] as $stanza) {
            $fields = [];
            $duplicate = false;
            foreach (explode("\n", $stanza) as $line) {
                if (preg_match('/\A(Package|Version|Status|Architecture): (.*)\z/', $line, $field) === 1) {
                    $duplicate = $duplicate || isset($fields[$field[1]]);
                    $fields[$field[1]] = $field[2];
                }
            }
            $name = $fields['Package'] ?? null;
            if ($name !== null && preg_match('/\Alibapache2-mod-php[0-9]+(?:\.[0-9]+)?\z/', $name) === 1) {
                if ($duplicate) {
                    return $unknown('package_status_ambiguous');
                }
                $candidates[] = $fields;
            }
        }
        $sources = [['locator' => '/var/lib/dpkg/status', 'content' => $status]];
        $owners = [];
        foreach ($candidates as $fields) {
            if (!DpkgPackageStatus::hasVerifiedIntegrityStatus($fields['Status'] ?? '')) {
                continue;
            }
            $name = $fields['Package'] ?? null;
            if ($name === null) {
                continue;
            }
            $matching = array_values(array_filter($packages, static fn(array $package): bool => $package['name'] === $name));
            if (count($matching) !== 1 || $matching[0]['version'] !== ($fields['Version'] ?? null)) {
                continue;
            }
            $metadataPaths = ['/var/lib/dpkg/info/' . $name . '.md5sums'];
            $architecture = $fields['Architecture'] ?? '';
            if (preg_match('/\A[a-z0-9-]{1,32}\z/', $architecture) === 1) {
                $metadataPaths[] = '/var/lib/dpkg/info/' . $name . ':' . $architecture . '.md5sums';
            }
            $checksums = [];
            foreach ($metadataPaths as $metadataPath) {
                if (file_exists($this->rootPath($metadataPath)) || is_link($this->rootPath($metadataPath))) {
                    $checksums[$metadataPath] = $this->readMetadata($metadataPath);
                }
            }
            if (count($checksums) !== 1 || ($contents = array_values($checksums)[0]) === null || !str_ends_with($contents, "\n")) {
                continue;
            }
            $expected = [];
            $malformed = false;
            foreach (explode("\n", rtrim($contents, "\n")) as $line) {
                if (preg_match('/\A([a-f0-9]{32})  ([^\x00-\x1F\x7F]{1,512})\z/', $line, $entry) !== 1) {
                    $malformed = true;
                    break;
                }
                if ($entry[2] === ltrim($path, '/')) {
                    $expected[] = $entry[1];
                }
            }
            if ($malformed || count($expected) !== 1) {
                continue;
            }
            $owners[] = [
                'name' => $name,
                'version' => $matching[0]['version'],
                'expected_md5' => $expected[0],
                'checksums_locator' => (string) array_key_first($checksums),
                'checksums_content' => $contents,
            ];
        }
        if (count($owners) !== 1) {
            return ['provenance' => self::unknown($owners === [] ? 'package_ownership_unavailable' : 'package_ownership_ambiguous'), 'sources' => $sources];
        }
        $owner = $owners[0];
        $sources[] = ['locator' => $owner['checksums_locator'], 'content' => $owner['checksums_content']];
        if (!$this->safeRegularPath($path)) {
            return ['provenance' => self::unknown('executable_identity_unavailable'), 'sources' => $sources];
        }
        $installed = $this->fingerprint($this->rootPath($path));
        $sources[] = ['locator' => $path . ':fingerprint', 'content' => $installed === null ? null : json_encode($installed, JSON_THROW_ON_ERROR)];
        $proof = self::unknown('binary_integrity_unavailable');
        if ($installed !== null && $installed['md5'] === $owner['expected_md5']) {
            $proof = [
                'verified' => true,
                'package_name' => $owner['name'],
                'package_version' => $owner['version'],
                'executable_path' => $path,
                'method' => 'dpkg_md5sums_installed_module',
                'reason' => 'local_package_integrity_matched',
                'trust_boundary' => 'local_package_database',
                'evidence_source_ids' => [],
            ];
        }

        return ['provenance' => $proof, 'sources' => $sources];
    }

    private function rootPath(string $path): string
    {
        return rtrim($this->root, '/') . $path;
    }

    private function safeRegularPath(string $path, bool $directory = false): bool
    {
        $current = rtrim($this->root, '/');
        foreach (explode('/', ltrim($path, '/')) as $segment) {
            if ($segment === '' || $segment === '.' || $segment === '..') {
                return false;
            }
            $current .= '/' . $segment;
            if (is_link($current)) {
                return false;
            }
        }

        return $directory ? is_dir($current) : is_file($current);
    }

    /** @param int<1, 8388608> $maxBytes */
    private function readMetadata(string $path, int $maxBytes = self::MAX_METADATA_BYTES): ?string
    {
        if (!$this->safeRegularPath($path)) {
            return null;
        }
        $contents = @file_get_contents($this->rootPath($path), false, null, 0, $maxBytes + 1);

        return is_string($contents) && strlen($contents) <= $maxBytes ? $contents : null;
    }

    /** @return FileFingerprint|null */
    private function fingerprint(string $path): ?array
    {
        $file = @fopen($path, 'rb');
        if (!is_resource($file)) {
            return null;
        }
        try {
            $before = fstat($file);
            if ($before === false || ($before['mode'] & 0170000) !== 0100000 || $before['size'] < 64
                || $before['size'] > self::MAX_BINARY_BYTES || $before['size'] > $this->remainingHashBytes) {
                return null;
            }
            $md5 = hash_init('md5');
            $sha256 = hash_init('sha256');
            $read = 0;
            while (!feof($file)) {
                $bytes = fread($file, min(65_536, $this->remainingHashBytes + 1));
                if ($bytes === false || ($bytes === '' && !feof($file))) {
                    return null;
                }
                $length = strlen($bytes);
                $this->remainingHashBytes -= $length;
                $read += $length;
                if ($this->remainingHashBytes < 0 || $read > self::MAX_BINARY_BYTES) {
                    return null;
                }
                if ($read === $length && (substr($bytes, 0, 4) !== "\x7fELF" || !in_array(ord($bytes[4] ?? "\0"), [1, 2], true)
                    || !in_array(ord($bytes[5] ?? "\0"), [1, 2], true) || ($bytes[6] ?? '') !== "\x01")) {
                    return null;
                }
                hash_update($md5, $bytes);
                hash_update($sha256, $bytes);
            }
            $after = fstat($file);
            clearstatcache(true, $path);
            $current = @stat($path);
            if ($after === false || $current === false || $read !== $before['size']) {
                return null;
            }
            foreach (['dev', 'ino', 'size', 'mtime', 'ctime'] as $key) {
                if ($before[$key] !== $after[$key] || $before[$key] !== $current[$key]) {
                    return null;
                }
            }

            return ['md5' => hash_final($md5), 'sha256' => hash_final($sha256), 'dev' => $before['dev'], 'ino' => $before['ino'], 'size' => $before['size']];
        } finally {
            fclose($file);
        }
    }
}
