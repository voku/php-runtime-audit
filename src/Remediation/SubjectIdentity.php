<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Remediation;

/**
 * Resolves an assessment's subject_id back to a human-readable label and the specific fact_ids
 * that identify it, purely from the report's own observation facts. This never trusts the
 * subject_id's shape to imply anything by itself; every label is only built from fact values
 * that are actually present, and a subject that cannot be correlated stays explicitly unknown
 * rather than guessed.
 *
 * @phpstan-type ReportFact array{fact_id: string, key: string, value: mixed, source_id: string}
 */
final readonly class SubjectIdentity
{
    private function __construct(
        public string $kind,
        public string $label,
        /** @var list<string> */
        public array $evidenceIds,
    ) {}

    /** @phpstan-param array<string, ReportFact> $byKey */
    public static function resolveIndexed(array $byKey, string $subjectId): self
    {
        if ($subjectId === 'local-host') {
            return new self('unknown', 'No runtime subject was identified on this host.', []);
        }

        if (str_starts_with($subjectId, 'cli-')) {
            return self::resolveById($byKey, $subjectId, 'runtime.cli.', 'cli', static fn(string $p, array $f): string => sprintf(
                'CLI binary %s (PHP %s)',
                self::value($f, $p . '.binary_path'),
                self::value($f, $p . '.version'),
            ), ['.version', '.binary_path']);
        }

        if (str_starts_with($subjectId, 'fpm-executable-')) {
            return self::resolveById($byKey, $subjectId, 'runtime.fpm_executable.', 'fpm-executable', static fn(string $p, array $f): string => sprintf(
                'PHP-FPM executable %s (PHP %s)',
                self::value($f, $p . '.binary_path'),
                self::value($f, $p . '.version'),
            ), ['.binary_path', '.version']);
        }

        if (str_starts_with($subjectId, 'package-')) {
            return self::resolvePackage($byKey, $subjectId);
        }

        if (str_starts_with($subjectId, 'apache-')) {
            return self::resolveApacheModule($byKey, $subjectId);
        }

        if (str_starts_with($subjectId, 'worker-')) {
            return self::resolveById($byKey, $subjectId, 'worker.', 'worker', static fn(string $p, array $f): string => sprintf(
                '%s worker (pid evidence; version %s)',
                strtoupper(self::value($f, $p . '.kind')),
                self::value($f, $p . '.version'),
            ), ['.kind', '.version', '.executable_path']);
        }

        return new self('unknown', 'Unrecognized runtime subject.', []);
    }

    /**
     * @phpstan-param array<string, ReportFact> $byKey
     * @phpstan-param callable(string, array<string, ReportFact>): string $label
     * @param list<string> $evidenceSuffixes
     */
    private static function resolveById(array $byKey, string $subjectId, string $prefix, string $kind, callable $label, array $evidenceSuffixes): self
    {
        foreach ($byKey as $key => $fact) {
            if (!str_starts_with($key, $prefix) || !str_ends_with($key, '.id') || ($fact['value'] ?? null) !== $subjectId) {
                continue;
            }
            $itemPrefix = substr($key, 0, -strlen('.id'));
            $evidenceIds = [];
            foreach ($evidenceSuffixes as $suffix) {
                $sibling = $byKey[$itemPrefix . $suffix] ?? null;
                if ($sibling !== null) {
                    $evidenceIds[] = $sibling['fact_id'];
                }
            }

            return new self($kind, SafeText::plain($label($itemPrefix, $byKey)), $evidenceIds);
        }

        return new self('unknown', 'No matching runtime fact was found for this subject.', []);
    }

    /** @phpstan-param array<string, ReportFact> $byKey */
    private static function resolvePackage(array $byKey, string $subjectId): self
    {
        for ($index = 0; $index < 512; ++$index) {
            $nameFact = $byKey['package.' . $index . '.name'] ?? null;
            $versionFact = $byKey['package.' . $index . '.version'] ?? null;
            if (!is_array($nameFact) || !is_array($versionFact)
                || !is_string($nameFact['value'] ?? null) || !is_string($versionFact['value'] ?? null)) {
                continue;
            }
            $architectureFact = $byKey['package.' . $index . '.architecture'] ?? null;
            $architecture = is_array($architectureFact) && is_string($architectureFact['value'] ?? null)
                ? $architectureFact['value']
                : null;
            $identity = $nameFact['value'] . "\0" . $versionFact['value']
                . ($architecture !== null ? "\0" . $architecture : '');
            $candidateId = 'package-' . substr(hash('sha256', $identity), 0, 20);
            if ($candidateId !== $subjectId) {
                continue;
            }

            $evidenceIds = [$nameFact['fact_id'], $versionFact['fact_id']];
            if (is_array($architectureFact)) {
                $evidenceIds[] = $architectureFact['fact_id'];
            }

            return new self(
                'package',
                SafeText::plain(sprintf(
                    'Installed package %s %s%s',
                    $nameFact['value'],
                    $versionFact['value'],
                    $architecture !== null ? ' (' . $architecture . ')' : '',
                )),
                $evidenceIds,
            );
        }

        return new self('unknown', 'No matching installed package was found for this subject.', []);
    }

    /** @phpstan-param array<string, ReportFact> $byKey */
    private static function resolveApacheModule(array $byKey, string $subjectId): self
    {
        if (preg_match('/\Aapache-([0-9]+-(?:[0-9]+|unknown))-([0-9]+)\z/D', $subjectId, $matches) !== 1) {
            return new self('unknown', 'Unrecognized Apache module subject.', []);
        }
        $workerId = 'worker-' . $matches[1];
        $moduleIndex = ((int) $matches[2]) - 1;
        foreach ($byKey as $key => $fact) {
            if (!str_starts_with($key, 'worker.') || !str_ends_with($key, '.id') || ($fact['value'] ?? null) !== $workerId) {
                continue;
            }
            $itemPrefix = substr($key, 0, -strlen('.id'));
            $modulesFact = $byKey[$itemPrefix . '.apache_php_modules'] ?? null;
            $modules = $modulesFact !== null && is_array($modulesFact['value']) ? $modulesFact['value'] : [];
            $modulePath = is_string($modules[$moduleIndex] ?? null) ? $modules[$moduleIndex] : null;
            $evidenceIds = $modulesFact !== null ? [$modulesFact['fact_id']] : [];

            return new self(
                'apache-module',
                SafeText::plain($modulePath !== null
                    ? sprintf('Apache PHP module %s', $modulePath)
                    : 'An Apache worker\'s loaded PHP module (path not recorded).'),
                $evidenceIds,
            );
        }

        return new self('unknown', 'No matching Apache worker was found for this subject.', []);
    }

    /** @phpstan-param array<string, ReportFact> $facts */
    private static function value(array $facts, string $key): string
    {
        $value = $facts[$key]['value'] ?? null;

        return is_string($value) ? $value : 'unknown';
    }
}
