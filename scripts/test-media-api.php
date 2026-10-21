<?php

// Run with: php scripts/test-media-api.php
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit;
}

$root = sys_get_temp_dir() . '/historiek-api-' . bin2hex(random_bytes(8));
mkdir($root);
mkdir($root . '/admin');
mkdir($root . '/private');
mkdir($root . '/sessions');
mkdir($root . '/concerts');
foreach (['api.php', 'media.php'] as $filename) {
    copy(__DIR__ . '/../admin/' . $filename, $root . '/admin/' . $filename);
}
file_put_contents($root . '/concertData.json', json_encode(['concerts' => [['postcard_img' => 'poster.jpg']]]));
file_put_contents($root . '/concerts/poster.jpg', 'used');
file_put_contents($root . '/concerts/orphan.jpg', 'unused');
session_save_path($root . '/sessions');
session_id(bin2hex(random_bytes(16)));
session_start();
$_SESSION['admin_user'] = 'fixture-admin';
$_SESSION['csrf_token'] = 'fixture-csrf';
$cookie = 'PHPSESSID=' . session_id();
session_write_close();
$socket = stream_socket_server('tcp://127.0.0.1:0', $errorCode, $errorMessage);
if ($socket === false) {
    throw new RuntimeException($errorMessage);
}
$address = stream_socket_get_name($socket, false);
fclose($socket);
$process = proc_open(
    [PHP_BINARY, '-d', 'session.save_path=' . $root . '/sessions', '-S', $address, '-t', $root],
    [0 => ['pipe', 'r'], 1 => ['file', $root . '/server.log', 'a'], 2 => ['file', $root . '/server.log', 'a']],
    $pipes
);
$checks = 0;
function check_api(bool $ok, string $message): void {
    global $checks;
    $checks++;
    if (!$ok) throw new RuntimeException($message);
}
function request_api(string $action, string $method = 'GET', ?array $input = null, bool $authenticated = true, bool $csrf = true): array {
    global $address, $cookie;
    $headers = "Content-Type: application/json\r\n";
    if ($authenticated) $headers .= 'Cookie: ' . $cookie . "\r\n";
    if ($csrf) $headers .= "X-CSRF-Token: fixture-csrf\r\n";
    $context = stream_context_create(['http' => [
        'method' => $method,
        'header' => $headers,
        'content' => $input === null ? '' : json_encode($input),
        'ignore_errors' => true,
        'timeout' => 5,
    ]]);
    $response = file_get_contents('http://' . $address . '/admin/api.php?action=' . $action, false, $context);
    preg_match('/\s(\d{3})\s/', $http_response_header[0], $matches);
    return [(int) $matches[1], json_decode($response, true)];
}
try {
    if (!is_resource($process)) throw new RuntimeException('Cannot start fixture server.');
    fclose($pipes[0]);
    $ready = false;
    for ($attempt = 0; $attempt < 50; $attempt++) {
        $connection = @stream_socket_client('tcp://' . $address, $code, $message, 0.1);
        if ($connection !== false) {
            fclose($connection);
            $ready = true;
            break;
        }
        usleep(100000);
    }
    check_api($ready, 'Fixture server must become responsive.');
    check_api(request_api('media_list', 'GET', null, false)[0] === 401, 'Anonymous listing denied.');
    check_api(request_api('media_delete', 'POST', ['file' => 'orphan.jpg'], false)[0] === 401, 'Anonymous deletion denied.');
    [$status, $data] = request_api('media_list');
    check_api($status === 200 && count($data['files']) === 2, 'Authenticated inventory returns all files.');
    check_api(array_keys($data['files'][0]) === ['filename', 'extension', 'size', 'visible', 'referenced', 'url'], 'Inventory JSON shape.');
    check_api($data['files'][0]['url'] === '../concerts/orphan.jpg', 'Standalone links are relative to admin, not a fixed hostname.');
    file_put_contents($root . '/concerts/foto #1%.jpg', 'image');
    [, $encoded] = request_api('media_list');
    check_api($encoded['files'][0]['url'] === '../concerts/foto%20%231%25.jpg', 'Special characters are encoded in standalone URLs.');
    $preview = file_get_contents('http://' . $address . '/concerts/foto%20%231%25.jpg');
    check_api($preview === 'image', 'Encoded preview URL serves the exact file.');
    unlink($root . '/concerts/foto #1%.jpg');
    check_api(request_api('media_delete')[0] === 405, 'GET cannot delete.');
    check_api(request_api('media_delete', 'POST', ['file' => 'orphan.jpg'], true, false)[0] === 403, 'Deletion requires CSRF token.');
    check_api(request_api('media_delete', 'POST', ['file' => 'poster.jpg'])[0] === 409, 'Used media protected.');
    check_api(request_api('media_delete', 'POST', ['file' => '../concertData.json'])[0] === 409, 'Traversal rejected.');
    check_api(request_api('media_delete', 'POST', ['file' => []])[0] === 400, 'Invalid filenames rejected.');
    [$status, $data] = request_api('media_delete', 'POST', ['file' => 'orphan.jpg']);
    check_api($status === 200 && $data['ok'] === true && !file_exists($root . '/concerts/orphan.jpg'), 'Authenticated orphan deletion succeeds.');
    check_api(strpos(file_get_contents($root . '/private/audit.log'), 'delete_orphaned_media') !== false, 'Deletion is audited.');
    file_put_contents($root . '/concertData.json', '{');
    check_api(request_api('media_list')[0] === 500, 'Invalid concert data reports inventory error.');
    check_api(request_api('media_delete', 'POST', ['file' => 'poster.jpg'])[0] === 409, 'Invalid concert data blocks deletion.');
    check_api(is_file($root . '/concerts/poster.jpg'), 'Used media remains intact.');
    echo "OK: $checks standalone API checks passed.\n";
} finally {
    if (is_resource($process)) {
        proc_terminate($process);
        proc_close($process);
    }
    $entries = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($entries as $entry) {
        $entry->isDir() ? rmdir($entry->getPathname()) : unlink($entry->getPathname());
    }
    rmdir($root);
}
