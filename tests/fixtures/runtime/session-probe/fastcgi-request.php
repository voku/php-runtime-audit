<?php

declare(strict_types=1);

/*
 * Minimal FastCGI client for the disposable session scenarios: sends one GET-style request to
 * a PHP-FPM pool listening on the container's loopback and prints the response body.
 *
 * Usage: php fastcgi-request.php <port> <script-filename> <query-string>
 */

if (!isset($argv[1], $argv[2], $argv[3]) || preg_match('/\A[0-9]{2,5}\z/', $argv[1]) !== 1) {
    fwrite(STDERR, "Usage: php fastcgi-request.php <port> <script-filename> <query-string>\n");
    exit(2);
}
$socket = @stream_socket_client('tcp://127.0.0.1:' . $argv[1], $errno, $error, 5);
if ($socket === false) {
    fwrite(STDERR, 'FastCGI connect failed: ' . $error . "\n");
    exit(1);
}
stream_set_timeout($socket, 5);
$record = static fn(int $type, string $content): string => pack('CCnnCx', 1, $type, 1, strlen($content), 0) . $content;
$length = static fn(string $value): string => strlen($value) < 128 ? chr(strlen($value)) : pack('N', strlen($value) | 0x80000000);
$params = '';
foreach ([
    'SCRIPT_FILENAME' => $argv[2],
    'SCRIPT_NAME' => '/' . basename($argv[2]),
    'REQUEST_METHOD' => 'GET',
    'QUERY_STRING' => $argv[3],
    'SERVER_PROTOCOL' => 'HTTP/1.1',
    'GATEWAY_INTERFACE' => 'CGI/1.1',
    'REMOTE_ADDR' => '127.0.0.1',
] as $name => $value) {
    $params .= $length($name) . $length($value) . $name . $value;
}
// BEGIN_REQUEST (responder, no keep-alive), PARAMS, empty PARAMS, empty STDIN.
fwrite($socket, $record(1, pack('nCx5', 1, 0)) . $record(4, $params) . $record(4, '') . $record(5, ''));
/**
 * Read exactly $length bytes or fail: network streams may return short reads.
 *
 * @param resource $socket
 */
function readExactly($socket, int $length): string
{
    $buffer = '';
    while (strlen($buffer) < $length) {
        $chunk = fread($socket, max(1, $length - strlen($buffer)));
        if (!is_string($chunk) || $chunk === '') {
            $meta = stream_get_meta_data($socket);
            fwrite(STDERR, 'FastCGI response ended early (' . ($meta['timed_out'] ? 'timeout' : 'EOF') . ").\n");
            exit(1);
        }
        $buffer .= $chunk;
    }

    return $buffer;
}

$stdout = '';
$ended = false;
while (!$ended) {
    $fields = unpack('Cversion/Ctype/nid/nlength/Cpadding', readExactly($socket, 8));
    if (!is_array($fields)) {
        fwrite(STDERR, "FastCGI record header could not be parsed.\n");
        exit(1);
    }
    $contentLength = is_int($fields['length'] ?? null) ? $fields['length'] : 0;
    $paddingLength = is_int($fields['padding'] ?? null) ? $fields['padding'] : 0;
    $content = $contentLength > 0 ? readExactly($socket, $contentLength) : '';
    if ($paddingLength > 0) {
        readExactly($socket, $paddingLength);
    }
    if ($fields['type'] === 6) {
        $stdout .= $content;
    }
    // END_REQUEST closes the response.
    $ended = $fields['type'] === 3;
}
$separator = strpos($stdout, "\r\n\r\n");
if ($separator === false) {
    fwrite(STDERR, "FastCGI response had no header separator.\n");
    exit(1);
}
echo substr($stdout, $separator + 4), "\n";
