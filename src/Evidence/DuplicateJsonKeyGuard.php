<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

use InvalidArgumentException;

/** Rejects repeated object names before PHP's JSON decoder collapses them. */
final class DuplicateJsonKeyGuard
{
    private int $offset = 0;
    private int $length;

    private function __construct(private readonly string $json)
    {
        $this->length = strlen($json);
    }

    public static function assertNoDuplicates(string $json): void
    {
        $guard = new self($json);
        $guard->parseValue(0);
        $guard->skipWhitespace();
        if ($guard->offset !== $guard->length) {
            throw new InvalidArgumentException('JSON has trailing data.');
        }
    }

    private function parseValue(int $depth): void
    {
        if ($depth > 64) {
            throw new InvalidArgumentException('JSON nesting exceeds the maximum depth of 64.');
        }
        $this->skipWhitespace();
        $character = $this->json[$this->offset] ?? '';

        if ($character === '{') {
            $this->parseObject($depth + 1);
            return;
        }
        if ($character === '[') {
            $this->parseArray($depth + 1);
            return;
        }
        if ($character === '"') {
            $this->parseString();
            return;
        }

        $start = $this->offset;
        while ($this->offset < $this->length && !str_contains(" \t\r\n,]}", $this->json[$this->offset])) {
            $this->offset++;
        }
        if ($this->offset === $start) {
            throw new InvalidArgumentException('JSON contains an invalid value.');
        }
    }

    private function parseObject(int $depth): void
    {
        $this->offset++;
        $this->skipWhitespace();
        if (($this->json[$this->offset] ?? '') === '}') {
            $this->offset++;
            return;
        }

        $keys = [];
        while (true) {
            $this->skipWhitespace();
            if (($this->json[$this->offset] ?? '') !== '"') {
                throw new InvalidArgumentException('JSON object keys must be strings.');
            }
            $key = json_decode($this->readStringToken(), true, 64, JSON_THROW_ON_ERROR);
            if (!is_string($key)) {
                throw new InvalidArgumentException('JSON object contains an invalid key.');
            }
            if (array_key_exists($key, $keys)) {
                throw new InvalidArgumentException('JSON contains a duplicate object key.');
            }
            $keys[$key] = true;

            $this->skipWhitespace();
            if (($this->json[$this->offset] ?? '') !== ':') {
                throw new InvalidArgumentException('JSON object key is missing its value separator.');
            }
            $this->offset++;
            $this->parseValue($depth);
            $this->skipWhitespace();
            $separator = $this->json[$this->offset] ?? '';
            if ($separator === '}') {
                $this->offset++;
                return;
            }
            if ($separator !== ',') {
                throw new InvalidArgumentException('JSON object contains an invalid separator.');
            }
            $this->offset++;
        }
    }

    private function parseArray(int $depth): void
    {
        $this->offset++;
        $this->skipWhitespace();
        if (($this->json[$this->offset] ?? '') === ']') {
            $this->offset++;
            return;
        }

        while (true) {
            $this->parseValue($depth);
            $this->skipWhitespace();
            $separator = $this->json[$this->offset] ?? '';
            if ($separator === ']') {
                $this->offset++;
                return;
            }
            if ($separator !== ',') {
                throw new InvalidArgumentException('JSON array contains an invalid separator.');
            }
            $this->offset++;
        }
    }

    private function parseString(): void
    {
        $this->readStringToken();
    }

    private function readStringToken(): string
    {
        $start = $this->offset++;
        while ($this->offset < $this->length) {
            $character = $this->json[$this->offset++];
            if ($character === '\\') {
                if ($this->offset >= $this->length) {
                    break;
                }
                $this->offset++;
                continue;
            }
            if ($character === '"') {
                return substr($this->json, $start, $this->offset - $start);
            }
        }

        throw new InvalidArgumentException('JSON contains an unterminated string.');
    }

    private function skipWhitespace(): void
    {
        while ($this->offset < $this->length && str_contains(" \t\r\n", $this->json[$this->offset])) {
            $this->offset++;
        }
    }
}
