<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Remediation;

/**
 * Bounds and neutralizes text pulled from a report JSON before it is ever placed into generated
 * output. The report is normally produced by this project's own collector, but this CLI accepts
 * it as plain stdin input and must not assume it is well-formed or benign: a malformed or
 * hand-crafted report must not be able to inject control characters, break Markdown structure,
 * or masquerade as a shell command if a reader copy-pastes report text.
 */
final class SafeText
{
    private const MAX_LENGTH = 512;

    /** Strip control characters and bound length; never returns executable-looking content. */
    public static function plain(string $value, int $maxLength = self::MAX_LENGTH): string
    {
        $stripped = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $value) ?? '';
        $stripped = str_replace(["\r\n", "\r"], "\n", $stripped);
        $stripped = preg_replace('/\n+/', ' ', $stripped) ?? '';
        $stripped = trim($stripped);
        if (strlen($stripped) > $maxLength) {
            $stripped = substr($stripped, 0, $maxLength) . '…';
        }

        return $stripped;
    }

    /** Escape Markdown-significant characters so untrusted text cannot alter document structure. */
    public static function markdown(string $value, int $maxLength = self::MAX_LENGTH): string
    {
        $plain = self::plain($value, $maxLength);

        return (string) preg_replace('/([\\\\`*_{}\[\]()#+!|<>~-])/', '\\\\$1', $plain);
    }

    /**
     * A conservative allowlist for identifiers (package names, version strings, file paths)
     * that are safe to display and to place inside an illustrative, non-executed example
     * command without risking shell metacharacter injection. Anything else is rejected rather
     * than silently stripped, so callers can fall back to "unknown" instead of a wrong display.
     */
    public static function isSafeIdentifier(string $value): bool
    {
        return $value !== '' && strlen($value) <= 256 && preg_match('/\A[A-Za-z0-9][A-Za-z0-9_.+:\/-]*\z/', $value) === 1;
    }
}
