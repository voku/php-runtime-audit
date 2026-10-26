<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\AuditProfiles;

final class AuditProfileSelector
{
    private const SAPI_PROFILES = [
        'apache-mod-php' => 'sapi-apache-mod-php',
        'apache2handler' => 'sapi-apache-mod-php',
        'fpm' => 'sapi-php-fpm',
        'fpm-fcgi' => 'sapi-php-fpm',
        'php-fpm' => 'sapi-php-fpm',
        'cli' => 'sapi-cli',
    ];

    private const DISTRIBUTION_PROFILES = [
        'alpine' => 'distribution-alpine',
        'almalinux' => 'distribution-rhel-family',
        'debian' => 'distribution-debian',
        'fedora' => 'distribution-rhel-family',
        'rocky' => 'distribution-rhel-family',
        'rhel' => 'distribution-rhel-family',
        'ubuntu' => 'distribution-ubuntu',
    ];

    public function select(AuditIntent $intent, AuditFacts $facts): AuditProfileSelection
    {
        $profiles = [];
        $unknownInputs = [];
        $profiles[$intent->value] = new SelectedProfile(
            $intent->value,
            sprintf('The caller requested the %s audit intent.', $intent->value),
        );

        if ($facts->phpVersion === null) {
            $unknownInputs[] = 'php_version';
        } elseif ($this->isSupportedTargetVersion($facts->phpVersion)) {
            $profiles['php-target-version'] = new SelectedProfile(
                'php-target-version',
                sprintf('The caller supplied PHP %s, within the PHP 8.2–8.5 target range.', $facts->phpVersion),
            );
        } else {
            $unknownInputs[] = 'php_version:unsupported';
        }

        if ($intent !== AuditIntent::SourceReview) {
            if ($facts->sapi === null) {
                $unknownInputs[] = 'sapi';
            } elseif (isset(self::SAPI_PROFILES[$facts->sapi])) {
                $profileId = self::SAPI_PROFILES[$facts->sapi];
                $profiles[$profileId] = new SelectedProfile(
                    $profileId,
                    sprintf('The caller supplied SAPI %s.', $facts->sapi),
                );
            } else {
                $unknownInputs[] = 'sapi:unsupported';
            }

            if ($facts->distribution === null) {
                $unknownInputs[] = 'distribution';
            } elseif (isset(self::DISTRIBUTION_PROFILES[$facts->distribution])) {
                $profileId = self::DISTRIBUTION_PROFILES[$facts->distribution];
                $profiles[$profileId] = new SelectedProfile(
                    $profileId,
                    sprintf('The caller supplied distribution %s.', $facts->distribution),
                );
            } else {
                $unknownInputs[] = 'distribution:unsupported';
            }

            if ($facts->vendor === null) {
                $unknownInputs[] = 'vendor';
            } else {
                $profiles['vendor-provenance'] = new SelectedProfile(
                    'vendor-provenance',
                    sprintf('The caller supplied package vendor %s.', $facts->vendor),
                );
            }

            if ($facts->container === Applicability::True) {
                $profiles['container'] = new SelectedProfile(
                    'container',
                    'The caller explicitly marked the audited runtime as containerized.',
                );
            } elseif ($facts->container === Applicability::Unknown) {
                $unknownInputs[] = 'container';
            }

            if ($facts->extensions === null) {
                $unknownInputs[] = 'extensions';
            } elseif ($facts->extensions !== []) {
                $profiles['php-extensions'] = new SelectedProfile(
                    'php-extensions',
                    'The caller supplied one or more enabled PHP extensions.',
                );
            }

            if ($facts->configuration === []) {
                $unknownInputs[] = 'configuration';
            } else {
                $profiles['configuration-facts'] = new SelectedProfile(
                    'configuration-facts',
                    'The caller supplied one or more named configuration facts.',
                );

                foreach ($facts->configuration as $name => $value) {
                    if ($value === Applicability::Unknown) {
                        $unknownInputs[] = 'configuration.' . $name;
                    }
                }
            }
        }

        if ($intent === AuditIntent::RuntimePatch) {
            // PRA-2 has no advisory source or independent vendor-backport verifier.
            $unknownInputs[] = 'vendor_backport_status';
        }

        ksort($profiles, SORT_STRING);
        $unknownInputs = array_values(array_unique($unknownInputs));
        sort($unknownInputs, SORT_STRING);

        return new AuditProfileSelection($intent, array_values($profiles), $unknownInputs);
    }

    private function isSupportedTargetVersion(string $version): bool
    {
        return preg_match('/\A8\.(?:2|3|4|5)\.\d+\z/', $version) === 1;
    }
}
