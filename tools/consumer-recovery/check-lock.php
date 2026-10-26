<?php

declare(strict_types=1);

// CI-only assertion, not a new product-specific governance mechanism.
if (!isset($argv[1]) || !is_file($argv[1])) {
    fwrite(STDERR, "Expected a Composer lockfile\n");
    exit(2);
}

$data = json_decode((string) file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);
$packages = [...($data['packages'] ?? []), ...($data['packages-dev'] ?? [])];
$matches = array_values(array_filter($packages, static fn (array $p): bool => ($p['name'] ?? null) === 'voku/agent-loop'));

if (count($matches) !== 1 || ($matches[0]['version'] ?? null) !== '0.20.70') {
    fwrite(STDERR, "Lock does not contain exactly one voku/agent-loop 0.20.70\n");
    exit(1);
}

$expected = 'd5e77d400ebd7bdbd8e5fe875a2e894e2b99f70e';
if (($matches[0]['source']['reference'] ?? null) !== $expected) {
    fwrite(STDERR, "Unexpected source commit for agent-loop 0.20.70\n");
    exit(1);
}

echo "PASS: Published agent-loop 0.20.70 and exact release source\n";
