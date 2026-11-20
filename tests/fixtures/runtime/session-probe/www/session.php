<?php

declare(strict_types=1);

/*
 * Benign ground-truth probe for the disposable session scenarios (issue #38).
 *
 * op=info  reports the pool's live session settings without starting a session.
 * op=write stores one plain string in a fresh session; op=read tries to read it back.
 *
 * It never stores objects. ini_get() is deliberately avoided: a shared OPcache can fold
 * ini_get('session.*') at compile time, so another pool's value would be reported;
 * ini_get_all() returns this request's live value.
 */

$settings = ini_get_all('session');
$live = static function (string $name) use ($settings): ?string {
    $entry = is_array($settings) ? ($settings[$name] ?? null) : null;

    return is_array($entry) && is_string($entry['local_value'] ?? null) ? $entry['local_value'] : null;
};
$operation = is_string($_GET['op'] ?? null) ? $_GET['op'] : 'info';
$result = [
    'operation' => $operation,
    'save_path' => $live('session.save_path'),
    'serializer' => $live('session.serialize_handler'),
];
if ($operation === 'write' || $operation === 'read') {
    $requestedId = is_string($_GET['id'] ?? null) ? $_GET['id'] : 'praprobe';
    session_id((string) preg_replace('/[^a-z0-9]/', '', $requestedId));
    $result['started'] = @session_start();
    if ($operation === 'write' && $result['started']) {
        $_SESSION['probe'] = 'pra-ground-truth';
    }
    $result['read_back'] = ($_SESSION['probe'] ?? null) === 'pra-ground-truth';
    if ($result['started']) {
        session_write_close();
    }
}
header('Content-Type: application/json');
echo json_encode($result, JSON_THROW_ON_ERROR);
