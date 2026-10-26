<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

final class EvidenceCli
{
    /** @param list<string> $arguments */
    public function run(array $arguments): int
    {
        if (count($arguments) !== 2 || $arguments[0] !== 'validate') {
            return $this->emit(false, null, null, ['Usage: php bin/php-runtime-audit-evidence validate <local-json-file>'], 2);
        }

        $path = $arguments[1];
        if (preg_match('/\A[a-z][a-z0-9+.-]*:/i', $path) === 1) {
            return $this->emit(false, null, null, ['Input must be a local file path; stream wrappers are not accepted.'], 2);
        }
        if (str_starts_with($path, chr(92) . chr(92)) || str_starts_with($path, '//')) {
            return $this->emit(false, null, null, ['Input must be a local file path; UNC network paths are not accepted.'], 2);
        }

        $handle = @fopen($path, 'rb');
        if (!is_resource($handle)) {
            return $this->emit(false, null, null, ['Unable to open the caller-supplied evidence file.'], 2);
        }
        try {
            $json = stream_get_contents($handle, EvidenceValidator::MAX_INPUT_BYTES + 1);
        } finally {
            fclose($handle);
        }

        if (!is_string($json)) {
            return $this->emit(false, null, null, ['Unable to read the caller-supplied evidence file.'], 2);
        }

        $result = (new EvidenceValidator())->validate($json);
        return $this->emit($result->valid, $result->recordType, $result->schemaVersion, $result->errors, $result->valid ? 0 : 1);
    }

    /** @param list<string> $errors */
    private function emit(bool $valid, ?RecordType $type, ?string $version, array $errors, int $exitCode): int
    {
        $json = json_encode([
            'valid' => $valid,
            'record_type' => $type?->value,
            'schema_version' => $version,
            'errors' => $errors,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        fwrite(STDOUT, ($json === false ? '{"valid":false,"errors":["Unable to encode result."]}' : $json) . PHP_EOL);

        return $exitCode;
    }
}
