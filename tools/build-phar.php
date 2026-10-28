#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * @return never
 */
function buildFailure(string $message): never
{
    throw new RuntimeException($message);
}

/**
 * @param array<string, string> $files
 */
function collectDirectory(string $projectRoot, string $directory, string $internalPrefix, array &$files): void
{
    $sourceDirectory = $projectRoot . DIRECTORY_SEPARATOR . $directory;
    $resolvedDirectory = realpath($sourceDirectory);
    if ($resolvedDirectory === false || !is_dir($resolvedDirectory) || is_link($sourceDirectory)) {
        buildFailure(sprintf('Required PHAR source directory is missing or unsafe: %s', $directory));
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($resolvedDirectory, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY,
    );

    foreach ($iterator as $entry) {
        if ($entry->isLink()) {
            buildFailure(sprintf('PHAR source trees must not contain symbolic links: %s', $entry->getPathname()));
        }
        if (!$entry->isFile()) {
            continue;
        }

        $subPath = str_replace(DIRECTORY_SEPARATOR, '/', $iterator->getSubPathName());
        if ($directory === 'vendor' && ($subPath === 'bin' || str_starts_with($subPath, 'bin/'))) {
            continue;
        }

        $internalPath = $internalPrefix . '/' . $subPath;
        if (str_starts_with($internalPath, '/')
            || str_contains($internalPath, "\0")
            || preg_match('#(?:^|/)\.\.(?:/|$)#', $internalPath) === 1
            || str_contains($internalPath, '\\')) {
            buildFailure(sprintf('Invalid PHAR internal path: %s', $internalPath));
        }

        $resolvedFile = realpath($entry->getPathname());
        if ($resolvedFile === false || !str_starts_with($resolvedFile, $resolvedDirectory . DIRECTORY_SEPARATOR)) {
            buildFailure(sprintf('PHAR source file escapes its declared directory: %s', $entry->getPathname()));
        }

        if (array_key_exists($internalPath, $files)) {
            buildFailure(sprintf('Duplicate PHAR internal path: %s', $internalPath));
        }
        $files[$internalPath] = $resolvedFile;
    }
}

/**
 * @param array<string, string> $files
 */
function collectFile(string $projectRoot, string $path, array &$files): void
{
    $sourcePath = $projectRoot . DIRECTORY_SEPARATOR . $path;
    $resolvedPath = realpath($sourcePath);
    if ($resolvedPath === false
        || !is_file($resolvedPath)
        || is_link(dirname($sourcePath))
        || is_link($sourcePath)
        || !str_starts_with($resolvedPath, $projectRoot . DIRECTORY_SEPARATOR)) {
        buildFailure(sprintf('Required PHAR source file is missing or unsafe: %s', $path));
    }

    $internalPath = str_replace(DIRECTORY_SEPARATOR, '/', $path);
    if (array_key_exists($internalPath, $files)) {
        buildFailure(sprintf('Duplicate PHAR internal path: %s', $internalPath));
    }
    $files[$internalPath] = $resolvedPath;
}

try {
    if (PHP_SAPI !== 'cli') {
        buildFailure('The PHAR builder must run from the command line.');
    }
    if (!extension_loaded('phar') || (string) ini_get('phar.readonly') !== '0') {
        buildFailure('Build with the Phar extension enabled and phar.readonly=0.');
    }
    if (!isset($argv, $argc) || !is_array($argv) || $argc !== count($argv) || $argc > 2) {
        buildFailure('Usage: php -d phar.readonly=0 tools/build-phar.php [output.phar]');
    }

    $projectRoot = realpath(dirname(__DIR__));
    if ($projectRoot === false) {
        buildFailure('Unable to resolve the project root.');
    }

    $vendorInstalledFile = $projectRoot . '/vendor/composer/installed.json';
    if (!is_file($vendorInstalledFile)) {
        buildFailure('Composer dependencies are missing; install production dependencies first.');
    }
    $installedJson = file_get_contents($vendorInstalledFile);
    if (!is_string($installedJson)) {
        buildFailure('Unable to read Composer installed package metadata.');
    }
    $installed = json_decode($installedJson, true, 512, JSON_THROW_ON_ERROR);
    if (!is_array($installed) || ($installed['dev'] ?? null) !== false) {
        buildFailure('Install dependencies with composer install --no-dev before building the PHAR.');
    }

    $requestedOutput = $argv[1] ?? sys_get_temp_dir() . '/php-runtime-audit.phar';
    if ($requestedOutput === '' || str_contains($requestedOutput, "\0")) {
        buildFailure('The PHAR output path must be a non-empty local path.');
    }

    $outputDirectory = realpath(dirname($requestedOutput));
    if ($outputDirectory === false || !is_dir($outputDirectory)) {
        buildFailure('The PHAR output directory must already exist.');
    }
    $outputPath = $outputDirectory . DIRECTORY_SEPARATOR . basename($requestedOutput);
    if (strtolower(pathinfo($outputPath, PATHINFO_EXTENSION)) !== 'phar') {
        buildFailure('The PHAR output filename must end in .phar.');
    }
    if (is_link($outputPath) || (file_exists($outputPath) && !is_file($outputPath))) {
        buildFailure('The PHAR output path must be a regular file path, not a symlink or directory.');
    }

    $files = [];
    collectDirectory($projectRoot, 'src', 'src', $files);
    collectDirectory($projectRoot, 'resources', 'resources', $files);
    collectDirectory($projectRoot, 'vendor', 'vendor', $files);
    foreach ([
        'bin/php-runtime-audit',
        'bin/php-runtime-audit-evidence',
        'bin/php-runtime-audit-inventory',
        'bin/php-runtime-audit-report',
        'LICENSE',
    ] as $path) {
        collectFile($projectRoot, $path, $files);
    }

    ksort($files, SORT_STRING);

    $temporaryBase = tempnam($outputDirectory, '.php-runtime-audit-');
    if ($temporaryBase === false) {
        buildFailure('Unable to allocate a temporary PHAR output file.');
    }
    $temporaryPath = $temporaryBase . '.phar';
    if (!rename($temporaryBase, $temporaryPath)) {
        unlink($temporaryBase);
        buildFailure('Unable to prepare the temporary PHAR output file.');
    }
    if (!unlink($temporaryPath)) {
        buildFailure('Unable to initialize the temporary PHAR output file.');
    }

    try {
        $phar = new Phar($temporaryPath, 0, 'php-runtime-audit.phar');
        $phar->startBuffering();
        $phar->setSignatureAlgorithm(Phar::SHA256);
        $phar->setMetadata([
            'build_commit' => getenv('PHP_RUNTIME_AUDIT_BUILD_SHA') ?: 'local',
            'package' => 'voku/php-runtime-audit',
        ]);

        foreach ($files as $internalPath => $sourcePath) {
            $phar->addFile($sourcePath, $internalPath);
        }

        $stub = <<<'STUB'
#!/usr/bin/env php
<?php
Phar::mapPhar('php-runtime-audit.phar');

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "php-runtime-audit.phar must run from the command line.\n");
    exit(2);
}
if (!isset($argv, $argc) || !is_array($argv) || $argc !== count($argv)) {
    fwrite(STDERR, "CLI argument capture is unavailable; enable register_argc_argv for this command.\n");
    exit(2);
}

$commands = [
    'inventory' => 'php-runtime-audit-inventory',
    'report' => 'php-runtime-audit-report',
    'evidence' => 'php-runtime-audit-evidence',
    'profile' => 'php-runtime-audit',
];
$command = $argv[1] ?? 'inventory';
if ($command === '--help' || $command === '-h') {
    fwrite(STDOUT, "Usage: php php-runtime-audit.phar [inventory|report|evidence|profile] [arguments]\n");
    exit(0);
}
if (!is_string($command) || !array_key_exists($command, $commands)) {
    fwrite(STDERR, "Unknown command. Use --help to list inventory, report, evidence, and profile.\n");
    exit(2);
}

array_splice($argv, 1, 1);
$argv[0] = 'bin/' . $commands[$command];
$argc = count($argv);
$_SERVER['argv'] = $argv;
$_SERVER['argc'] = $argc;
$GLOBALS['argv'] = $argv;
$GLOBALS['argc'] = $argc;
require 'phar://php-runtime-audit.phar/' . $argv[0];
__HALT_COMPILER();
STUB;
        $phar->setStub($stub);
        $phar->stopBuffering();
        unset($phar);

        if (!chmod($temporaryPath, 0755)) {
            buildFailure('Unable to mark the PHAR as executable.');
        }
        if (!rename($temporaryPath, $outputPath)) {
            buildFailure('Unable to move the completed PHAR into the requested output path.');
        }
    } catch (Throwable $error) {
        if (is_file($temporaryPath)) {
            unlink($temporaryPath);
        }
        throw $error;
    }

    $size = filesize($outputPath);
    if (!is_int($size)) {
        buildFailure('Unable to read the completed PHAR size.');
    }
    fwrite(STDOUT, sprintf("Built %s (%d bytes; %d files).\n", $outputPath, $size, count($files)));
} catch (Throwable $error) {
    fwrite(STDERR, 'build-phar: ' . $error->getMessage() . "\n");
    exit(1);
}
