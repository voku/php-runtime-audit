<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\AuditProfiles;

use InvalidArgumentException;
use LengthException;
use RuntimeException;

final readonly class ProfileContextBuilder
{
    public const DEFAULT_MAX_BYTES = 32768;

    private string $profileRoot;

    public function __construct(
        ?string $profileRoot = null,
        private int $maximumBytes = self::DEFAULT_MAX_BYTES,
    ) {
        $this->profileRoot = $profileRoot ?? dirname(__DIR__, 2) . '/resources/skills/php-runtime-audit/profiles';

        if ($this->maximumBytes < 1) {
            throw new InvalidArgumentException('The selected profile context byte budget must be positive.');
        }
    }

    /** @return array<string, string> Profile ID to bounded Markdown guidance. */
    public function load(AuditProfileSelection $selection): array
    {
        $isPharResource = str_starts_with($this->profileRoot, 'phar://');
        if ($isPharResource) {
            $runningArchive = \Phar::running(false);
            $expectedProfileRoot = $runningArchive === ''
                ? null
                : 'phar://' . $runningArchive . '/resources/skills/php-runtime-audit/profiles';
            if ($this->profileRoot !== $expectedProfileRoot || !is_dir($this->profileRoot)) {
                throw new RuntimeException('Profile resource root is missing or unreadable.');
            }
            $profileRoot = $this->profileRoot;
        } else {
            $profileRoot = realpath($this->profileRoot);
            if (is_link($this->profileRoot) || !is_string($profileRoot) || !is_dir($profileRoot)) {
                throw new RuntimeException('Profile resource root is missing or unreadable.');
            }
        }

        $context = [];
        $totalBytes = 0;

        foreach ($selection->profileIds() as $profileId) {
            if (strlen($profileId) > 64 || preg_match('/\A[a-z0-9]+(?:-[a-z0-9]+)*\z/', $profileId) !== 1) {
                throw new RuntimeException('Invalid selected profile identifier.');
            }

            $path = $profileRoot . '/' . $profileId . '.md';
            $resolvedPath = $isPharResource ? $path : realpath($path);
            $pathPrefix = $isPharResource
                ? rtrim($profileRoot, '/') . '/'
                : rtrim($profileRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
            if (is_link($path)
                || !is_string($resolvedPath)
                || !str_starts_with($resolvedPath, $pathPrefix)
                || !is_file($resolvedPath)
                || !is_readable($resolvedPath)) {
                throw new RuntimeException('Selected profile resource is missing or unreadable: ' . $profileId);
            }

            $handle = fopen($resolvedPath, 'rb');
            if (!is_resource($handle)) {
                throw new RuntimeException('Unable to read selected profile resource: ' . $profileId);
            }

            $openedStat = fstat($handle);
            $pathStat = lstat($resolvedPath);
            if (!is_array($openedStat)
                || !is_array($pathStat)
                || ($openedStat['mode'] & 0170000) !== 0100000
                || ($pathStat['mode'] & 0170000) !== 0100000
                || $openedStat['dev'] !== $pathStat['dev']
                || $openedStat['ino'] !== $pathStat['ino']) {
                fclose($handle);
                throw new RuntimeException('Selected profile resource is not a stable regular file: ' . $profileId);
            }

            $remainingBytes = $this->maximumBytes - $totalBytes;
            $readLimit = $remainingBytes === PHP_INT_MAX ? PHP_INT_MAX : max(1, $remainingBytes + 1);
            $content = fread($handle, $readLimit);
            fclose($handle);
            if (!is_string($content)) {
                throw new RuntimeException('Unable to read selected profile resource: ' . $profileId);
            }

            $totalBytes += strlen($content);
            if ($totalBytes > $this->maximumBytes) {
                throw new LengthException(sprintf(
                    'Selected profile context exceeds the %d-byte budget.',
                    $this->maximumBytes,
                ));
            }

            $context[$profileId] = trim($content);
        }

        return $context;
    }
}
