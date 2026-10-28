<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\RuntimeInventory;

/** Fixed, read-only system commands used by the local collector. */
enum ProcessCommand: string implements ProcessCommandSpec
{
    case PhpUsrBin = 'php-usr-bin';
    case PhpUsrLocalBin = 'php-usr-local-bin';
    case Php82 = 'php-8.2';
    case Php83 = 'php-8.3';
    case Php84 = 'php-8.4';
    case Php85 = 'php-8.5';
    case FpmUsrSbin = 'fpm-usr-sbin';
    case FpmUsrLocalSbin = 'fpm-usr-local-sbin';
    case Fpm82 = 'fpm-8.2';
    case Fpm83 = 'fpm-8.3';
    case Fpm84 = 'fpm-8.4';
    case Fpm85 = 'fpm-8.5';
    case Fpm82Alpine = 'fpm-82';
    case Fpm83Alpine = 'fpm-83';
    case Fpm84Alpine = 'fpm-84';
    case Fpm85Alpine = 'fpm-85';
    case DpkgPackages = 'dpkg-packages';
    case RpmPackages = 'rpm-packages';
    case ApkPackages = 'apk-packages';

    /** @return list<string> */
    public function argv(): array
    {
        // Keep this probe parseable on legacy PHP 5.x targets.
        $phpScript = 'echo json_encode(array("version" => PHP_VERSION, "sapi" => PHP_SAPI, "extensions" => get_loaded_extensions()));';

        return match ($this) {
            self::PhpUsrBin => ['/usr/bin/php', '-n', '-r', $phpScript],
            self::PhpUsrLocalBin => ['/usr/local/bin/php', '-n', '-r', $phpScript],
            self::Php82 => ['/usr/bin/php8.2', '-n', '-r', $phpScript],
            self::Php83 => ['/usr/bin/php8.3', '-n', '-r', $phpScript],
            self::Php84 => ['/usr/bin/php8.4', '-n', '-r', $phpScript],
            self::Php85 => ['/usr/bin/php8.5', '-n', '-r', $phpScript],
            self::FpmUsrSbin => ['/usr/sbin/php-fpm', '-n', '-v'],
            self::FpmUsrLocalSbin => ['/usr/local/sbin/php-fpm', '-n', '-v'],
            self::Fpm82 => ['/usr/sbin/php-fpm8.2', '-n', '-v'],
            self::Fpm83 => ['/usr/sbin/php-fpm8.3', '-n', '-v'],
            self::Fpm84 => ['/usr/sbin/php-fpm8.4', '-n', '-v'],
            self::Fpm85 => ['/usr/sbin/php-fpm8.5', '-n', '-v'],
            self::Fpm82Alpine => ['/usr/sbin/php-fpm82', '-n', '-v'],
            self::Fpm83Alpine => ['/usr/sbin/php-fpm83', '-n', '-v'],
            self::Fpm84Alpine => ['/usr/sbin/php-fpm84', '-n', '-v'],
            self::Fpm85Alpine => ['/usr/sbin/php-fpm85', '-n', '-v'],
            self::DpkgPackages => [
                '/usr/bin/dpkg-query', '-W', '-f=${Package}\t${Version}\t${Status}\n', '*php*',
            ],
            self::RpmPackages => [
                '/usr/bin/rpm', '-qa', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n', 'php*', 'mod_php*',
            ],
            self::ApkPackages => ['/sbin/apk', 'info', '-v'],
        };
    }

    public function timeoutSeconds(): float
    {
        return 3.0;
    }

    public function outputLimitBytes(): int
    {
        return match ($this) {
            self::DpkgPackages, self::RpmPackages, self::ApkPackages => 262_144,
            default => 16_384,
        };
    }

    public function executablePath(): string
    {
        return $this->argv()[0];
    }

    public function id(): string
    {
        return $this->value;
    }

    public function isPhpCli(): bool
    {
        return in_array($this, [self::PhpUsrBin, self::PhpUsrLocalBin, self::Php82, self::Php83, self::Php84, self::Php85], true);
    }

    public function isFpm(): bool
    {
        return str_starts_with($this->value, 'fpm-');
    }
}
