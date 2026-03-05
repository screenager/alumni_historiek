<?php
/**
 * Admin API for concertData.json
 * Dual mode:
 * - WordPress mode when wp-load.php is available
 * - Standalone mode with local password file/session auth otherwise
 */

function tryLoadWordPress(): bool {
    if (defined('ABSPATH') && function_exists('wp_get_current_user')) {
        return true;
    }

    $dir = __DIR__;
    for ($i = 0; $i < 8; $i++) {
        $candidate = $dir . '/wp-load.php';
        if (file_exists($candidate)) {
            require_once $candidate;
            return defined('ABSPATH') && function_exists('wp_get_current_user');
        }
        $dir = dirname($dir);
    }

    return false;
}

$IS_WP_MODE = tryLoadWordPress();

if (!$IS_WP_MODE) {
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.use_strict_mode', '1');
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        ini_set('session.cookie_secure', '1');
    }
    session_start();
}

function ensureDir(string $path): void {
    if (is_dir($path)) {
        return;
    }
    if (function_exists('wp_mkdir_p')) {
        wp_mkdir_p($path);
        return;
    }
    mkdir($path, 0755, true);
}

function storageInfo(bool $isWpMode): array {
    if ($isWpMode) {
        $mode = get_option('alumni_historiek_storage_mode', 'plugin');

        if ($mode === 'uploads') {
            $uploads = wp_upload_dir();
            $baseDir = trailingslashit($uploads['basedir']) . 'alumni-historiek';
            return [
                'base_dir' => $baseDir,
                'data_file' => $baseDir . '/concertData.json',
                'concerts_dir' => $baseDir . '/concerts',
                'private_dir' => $baseDir . '/private',
            ];
        }
    }

    $baseDir = dirname(__DIR__);
    return [
        'base_dir' => $baseDir,
        'data_file' => $baseDir . '/concertData.json',
        'concerts_dir' => $baseDir . '/concerts',
        'private_dir' => $baseDir . '/private',
    ];
}

$storage = storageInfo($IS_WP_MODE);
ensureDir($storage['concerts_dir']);
ensureDir($storage['private_dir']);

define('AUDIT_LOG', $storage['private_dir'] . '/audit.log');
define('DATA_FILE', $storage['data_file']);
define('CONCERTS_DIR', $storage['concerts_dir']);
define('PASSWD_FILE', $storage['private_dir'] . '/passwd');
define('RATE_LIMIT_FILE', $storage['private_dir'] . '/rate_limits.json');
define('MAX_LOGIN_ATTEMPTS', 5);
define('RATE_LIMIT_WINDOW', 900);

function auditLog(string $user, string $action, string $detail = ''): void {
    global $IS_WP_MODE;
    $ts = $IS_WP_MODE && function_exists('current_time') ? current_time('mysql') : date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $line = "[$ts] user=$user ip=$ip action=$action $detail\n";
    file_put_contents(AUDIT_LOG, $line, FILE_APPEND | LOCK_EX);
}

function jsonResponse(array $data, int $code = 200): void {
    global $IS_WP_MODE;
    if ($IS_WP_MODE && function_exists('status_header')) {
        status_header($code);
    } else {
        http_response_code($code);
    }
    header('Content-Type: application/json; charset=utf-8');
    if ($IS_WP_MODE && function_exists('wp_json_encode')) {
        echo wp_json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    } else {
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    }
    exit;
}

function requireAuth(): string {
    global $IS_WP_MODE;

    if ($IS_WP_MODE) {
        if (!is_user_logged_in()) {
            jsonResponse(['error' => 'Niet ingelogd in WordPress'], 401);
        }
        if (!current_user_can('manage_options')) {
            jsonResponse(['error' => 'Onvoldoende rechten'], 403);
        }
        $user = wp_get_current_user();
        return $user->user_login ?: 'wp-user';
    }

    if (empty($_SESSION['admin_user'])) {
        jsonResponse(['error' => 'Niet ingelogd'], 401);
    }
    return (string) $_SESSION['admin_user'];
}

function loadData(): array {
    $raw = @file_get_contents(DATA_FILE);
    $decoded = json_decode($raw ?: '', true);

    if (!is_array($decoded)) {
        return ['header' => ['h1' => '', 'swipe_hint' => '', 'flip_hint' => ''], 'concerts' => []];
    }

    if (!array_key_exists('concerts', $decoded)) {
        return ['header' => ['h1' => '', 'swipe_hint' => '', 'flip_hint' => ''], 'concerts' => $decoded];
    }

    if (!isset($decoded['header']) || !is_array($decoded['header'])) {
        $decoded['header'] = ['h1' => '', 'swipe_hint' => '', 'flip_hint' => ''];
    }

    return $decoded;
}

function loadConcerts(): array {
    $data = loadData();
    return $data['concerts'] ?? [];
}

function saveConcerts(array $concerts): void {
    $data = loadData();
    $data['concerts'] = $concerts;
    saveData($data);
}

function saveData(array $data): void {
    global $IS_WP_MODE;

    if ($IS_WP_MODE && function_exists('wp_json_encode')) {
        $json = wp_json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    } else {
        $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    }

    $json = preg_replace_callback(
        '/\{\s*"thumb":\s*"([^"]*)"\,\s*"full":\s*"([^"]*)"(?:\,\s*"alt":\s*"([^"]*)")?\s*\}/s',
        function ($m) {
            $line = '{ "thumb": "' . $m[1] . '", "full": "' . $m[2] . '"';
            if (!empty($m[3])) {
                $line .= ', "alt": "' . $m[3] . '"';
            }
            return $line . ' }';
        },
        (string) $json
    );

    $json = rtrim((string) $json) . "\n";
    file_put_contents(DATA_FILE, $json, LOCK_EX);
}

function generateStandaloneCsrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return (string) $_SESSION['csrf_token'];
}

function verifyCsrf(): void {
    global $IS_WP_MODE;

    if ($IS_WP_MODE) {
        $nonce = $_SERVER['HTTP_X_WP_NONCE'] ?? $_POST['_wpnonce'] ?? '';
        if (!wp_verify_nonce($nonce, 'alumni_historiek_api')) {
            jsonResponse(['error' => 'Ongeldige nonce — herlaad de pagina'], 403);
        }
        return;
    }

    $token = $_SERVER['HTTP_X_WP_NONCE']
        ?? $_SERVER['HTTP_X_CSRF_TOKEN']
        ?? $_POST['csrf_token']
        ?? '';

    if (empty($_SESSION['csrf_token']) || !hash_equals((string) $_SESSION['csrf_token'], (string) $token)) {
        jsonResponse(['error' => 'Ongeldige CSRF-token — herlaad de pagina'], 403);
    }
}

function requireCsrf(): void {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrf();
    }
}

function loadPasswd(): array {
    $users = [];
    if (!file_exists(PASSWD_FILE)) {
        return $users;
    }

    $lines = file(PASSWD_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) {
        return $users;
    }

    foreach ($lines as $line) {
        [$user, $hash] = explode(':', $line, 2);
        $users[trim($user)] = trim($hash);
    }
    return $users;
}

function getRateLimits(): array {
    if (!file_exists(RATE_LIMIT_FILE)) {
        return [];
    }
    $data = json_decode((string) file_get_contents(RATE_LIMIT_FILE), true);
    return is_array($data) ? $data : [];
}

function saveRateLimits(array $data): void {
    file_put_contents(RATE_LIMIT_FILE, json_encode($data), LOCK_EX);
}

function checkRateLimit(string $ip): void {
    $limits = getRateLimits();
    $now = time();

    foreach ($limits as $k => $entry) {
        if ($now - (int) ($entry['first'] ?? 0) > RATE_LIMIT_WINDOW) {
            unset($limits[$k]);
        }
    }
    saveRateLimits($limits);

    if (isset($limits[$ip]) && (int) ($limits[$ip]['count'] ?? 0) >= MAX_LOGIN_ATTEMPTS) {
        $remaining = RATE_LIMIT_WINDOW - ($now - (int) $limits[$ip]['first']);
        auditLog('(rate_limited)', 'login_blocked', "ip=$ip remaining={$remaining}s");
        jsonResponse(['error' => 'Te veel pogingen. Probeer opnieuw over ' . ceil($remaining / 60) . ' minuten.'], 429);
    }
}

function recordFailedLogin(string $ip): void {
    $limits = getRateLimits();
    $now = time();

    if (!isset($limits[$ip]) || ($now - (int) $limits[$ip]['first']) > RATE_LIMIT_WINDOW) {
        $limits[$ip] = ['count' => 1, 'first' => $now];
    } else {
        $limits[$ip]['count'] = ((int) $limits[$ip]['count']) + 1;
    }

    saveRateLimits($limits);
}

function clearRateLimit(string $ip): void {
    $limits = getRateLimits();
    unset($limits[$ip]);
    saveRateLimits($limits);
}

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';

header('X-Content-Type-Options: nosniff');

switch ($action) {
    case 'login':
        if ($IS_WP_MODE) {
            jsonResponse(['error' => 'Gebruik WordPress login via /wp-admin'], 405);
        }

        if ($method !== 'POST') {
            jsonResponse(['error' => 'POST vereist'], 405);
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        checkRateLimit($ip);

        $input = json_decode((string) file_get_contents('php://input'), true);
        $username = trim((string) ($input['username'] ?? ''));
        $password = (string) ($input['password'] ?? '');

        $users = loadPasswd();
        if (!isset($users[$username]) || !password_verify($password, $users[$username])) {
            recordFailedLogin($ip);
            auditLog($username ?: '(unknown)', 'login_failed');
            jsonResponse(['error' => 'Ongeldige gebruikersnaam of wachtwoord'], 401);
        }

        clearRateLimit($ip);
        session_regenerate_id(true);
        $_SESSION['admin_user'] = $username;
        $token = generateStandaloneCsrfToken();
        auditLog($username, 'login_success');
        jsonResponse(['ok' => true, 'user' => $username, 'csrf_token' => $token, 'mode' => 'standalone']);
        break;

    case 'logout':
        if ($IS_WP_MODE) {
            jsonResponse(['ok' => true]);
        }

        $user = $_SESSION['admin_user'] ?? '(unknown)';
        auditLog((string) $user, 'logout');
        session_destroy();
        jsonResponse(['ok' => true]);
        break;

    case 'status':
        if ($IS_WP_MODE) {
            if (is_user_logged_in() && current_user_can('manage_options')) {
                $user = wp_get_current_user();
                jsonResponse([
                    'loggedIn' => true,
                    'user' => $user->user_login,
                    'csrf_token' => wp_create_nonce('alumni_historiek_api'),
                    'mode' => 'wordpress',
                ]);
            }
            jsonResponse(['loggedIn' => false, 'mode' => 'wordpress']);
        }

        if (!empty($_SESSION['admin_user'])) {
            jsonResponse([
                'loggedIn' => true,
                'user' => $_SESSION['admin_user'],
                'csrf_token' => generateStandaloneCsrfToken(),
                'mode' => 'standalone',
            ]);
        }
        jsonResponse(['loggedIn' => false, 'mode' => 'standalone']);
        break;

    case 'list':
        requireAuth();
        jsonResponse(loadData());
        break;

    case 'update_header':
        if ($method !== 'POST') jsonResponse(['error' => 'POST vereist'], 405);
        $user = requireAuth();
        requireCsrf();

        $input = json_decode((string) file_get_contents('php://input'), true);
        $header = $input['header'] ?? null;
        if ($header === null) jsonResponse(['error' => 'header vereist'], 400);

        $data = loadData();
        $data['header'] = $header;
        saveData($data);

        auditLog($user, 'update_header', 'h1=' . ($header['h1'] ?? ''));
        jsonResponse(['ok' => true]);
        break;

    case 'get':
        requireAuth();
        $index = $_GET['index'] ?? null;
        if ($index === null) jsonResponse(['error' => 'Index ontbreekt'], 400);
        $concerts = loadConcerts();
        if (!isset($concerts[(int) $index])) jsonResponse(['error' => 'Concert niet gevonden'], 404);
        jsonResponse($concerts[(int) $index]);
        break;

    case 'update':
        if ($method !== 'POST') jsonResponse(['error' => 'POST vereist'], 405);
        $user = requireAuth();
        requireCsrf();

        $input = json_decode((string) file_get_contents('php://input'), true);
        $index = $input['index'] ?? null;
        $data = $input['data'] ?? null;

        if ($index === null || $data === null) jsonResponse(['error' => 'index en data vereist'], 400);

        $concerts = loadConcerts();
        if (!isset($concerts[(int) $index])) jsonResponse(['error' => 'Concert niet gevonden'], 404);

        $oldTitle = $concerts[(int) $index]['title'] ?? '(onbekend)';
        $oldConcert = $concerts[(int) $index];

        $original = $concerts[(int) $index];
        foreach ($data as $key => $value) {
            if (array_key_exists($key, $original) || ($value !== '' && $value !== null)) {
                $original[$key] = $value;
            }
        }
        foreach (array_keys($original) as $key) {
            if ($key !== 'images' && !array_key_exists($key, $data)) {
                unset($original[$key]);
            }
        }

        $oldImages = $oldConcert['images'] ?? [];
        $newImages = $data['images'] ?? [];
        $newPaths = array_merge(array_column($newImages, 'thumb'), array_column($newImages, 'full'));

        $concertFolder = ($oldConcert['year'] ?? '') . '_' . ($oldConcert['slug'] ?? '');
        if ($concertFolder !== '_') {
            foreach ($oldImages as $img) {
                foreach (['thumb', 'full'] as $key) {
                    $rel = $img[$key] ?? '';
                    if ($rel && !in_array($rel, $newPaths, true)) {
                        $absPath = CONCERTS_DIR . '/' . $concertFolder . '/' . $rel;
                        if (file_exists($absPath)) {
                            unlink($absPath);
                            auditLog($user, 'delete_image', "file=$concertFolder/$rel");
                        }
                    }
                }
            }
        }

        $oldPoster = $oldConcert['postcard_img'] ?? '';
        $newPoster = $data['postcard_img'] ?? '';
        if ($oldPoster && !$newPoster) {
            $posterPath = CONCERTS_DIR . '/' . $oldPoster;
            if (file_exists($posterPath)) {
                unlink($posterPath);
                auditLog($user, 'delete_poster', "file=$oldPoster");
            }
        }

        $concerts[(int) $index] = $original;
        saveConcerts($concerts);

        auditLog($user, 'update_concert', 'index=' . $index . ' title="' . ($data['title'] ?? '') . '" (was "' . $oldTitle . '")');
        jsonResponse(['ok' => true]);
        break;

    case 'add':
        if ($method !== 'POST') jsonResponse(['error' => 'POST vereist'], 405);
        $user = requireAuth();
        requireCsrf();

        $data = json_decode((string) file_get_contents('php://input'), true);
        if (!$data) jsonResponse(['error' => 'Ongeldige data'], 400);

        $concerts = loadConcerts();
        $concerts[] = $data;
        saveConcerts($concerts);

        $newIndex = count($concerts) - 1;
        auditLog($user, 'add_concert', 'index=' . $newIndex . ' title="' . ($data['title'] ?? '') . '"');
        jsonResponse(['ok' => true, 'index' => $newIndex]);
        break;

    case 'delete':
        if ($method !== 'POST') jsonResponse(['error' => 'POST vereist'], 405);
        $user = requireAuth();
        requireCsrf();

        $input = json_decode((string) file_get_contents('php://input'), true);
        $index = $input['index'] ?? null;
        if ($index === null) jsonResponse(['error' => 'index vereist'], 400);

        $concerts = loadConcerts();
        if (!isset($concerts[(int) $index])) jsonResponse(['error' => 'Concert niet gevonden'], 404);

        $concert = $concerts[(int) $index];
        $title = $concert['title'] ?? '(onbekend)';

        $concertFolder = ($concert['year'] ?? '') . '_' . ($concert['slug'] ?? '');
        if ($concertFolder !== '_') {
            $dirPath = CONCERTS_DIR . '/' . $concertFolder;
            if (is_dir($dirPath)) {
                $it = new RecursiveDirectoryIterator($dirPath, RecursiveDirectoryIterator::SKIP_DOTS);
                $files = new RecursiveIteratorIterator($it, RecursiveIteratorIterator::CHILD_FIRST);
                foreach ($files as $file) {
                    $file->isDir() ? rmdir($file->getRealPath()) : unlink($file->getRealPath());
                }
                rmdir($dirPath);
                auditLog($user, 'delete_directory', "folder=$concertFolder");
            }
        }

        array_splice($concerts, (int) $index, 1);
        saveConcerts($concerts);

        auditLog($user, 'delete_concert', 'index=' . $index . ' title="' . $title . '"');
        jsonResponse(['ok' => true]);
        break;

    case 'upload_poster':
        if ($method !== 'POST') jsonResponse(['error' => 'POST vereist'], 405);
        $user = requireAuth();
        requireCsrf();

        $concertFolder = $_POST['folder'] ?? '';
        if (!$concertFolder || !preg_match('/^[a-z0-9_]+$/i', $concertFolder)) {
            jsonResponse(['error' => 'Ongeldige concertmap'], 400);
        }

        $concertDir = CONCERTS_DIR . '/' . $concertFolder;
        ensureDir($concertDir);

        if (empty($_FILES['poster']) || $_FILES['poster']['error'] !== UPLOAD_ERR_OK) {
            $code = $_FILES['poster']['error'] ?? 'geen bestand';
            jsonResponse(['error' => "Upload mislukt (code $code)"], 400);
        }

        $tmpName = $_FILES['poster']['tmp_name'];
        $origName = $_FILES['poster']['name'];
        $info = getimagesize($tmpName);
        if (!$info || !in_array($info[2], [IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_WEBP, IMAGETYPE_GIF], true)) {
            jsonResponse(['error' => 'Geen geldig afbeeldingsformaat'], 400);
        }

        $src = loadImage($tmpName, $info[2]);
        if (!$src) jsonResponse(['error' => 'Kan afbeelding niet laden'], 500);

        $origW = imagesx($src);
        $origH = imagesy($src);

        $targetH = 1200;
        $targetW = (int) round($origW * ($targetH / $origH));

        $dest = imagecreatetruecolor($targetW, $targetH);
        imagecopyresampled($dest, $src, 0, 0, 0, 0, $targetW, $targetH, $origW, $origH);

        $posterPath = $concertDir . '/poster.jpg';
        imagejpeg($dest, $posterPath, 90);
        imagedestroy($dest);
        imagedestroy($src);

        auditLog($user, 'upload_poster', "folder=$concertFolder original=\"$origName\" size={$targetW}x{$targetH}");
        jsonResponse([
            'ok' => true,
            'postcard_img' => $concertFolder . '/poster.jpg',
            'width' => $targetW,
            'height' => $targetH,
        ]);
        break;

    case 'upload':
        if ($method !== 'POST') jsonResponse(['error' => 'POST vereist'], 405);
        $user = requireAuth();
        requireCsrf();

        $concertFolder = $_POST['folder'] ?? '';
        if (!$concertFolder || !preg_match('/^[a-z0-9_]+$/i', $concertFolder)) {
            jsonResponse(['error' => 'Ongeldige concertmap'], 400);
        }

        $picturesDir = CONCERTS_DIR . '/' . $concertFolder . '/pictures';
        ensureDir($picturesDir);

        $existing = glob($picturesDir . '/foto*.jpeg');
        $maxNum = 0;
        foreach ($existing ?: [] as $f) {
            if (preg_match('/foto(\d+)(?:_thumb)?\.jpeg$/', basename($f), $m)) {
                $maxNum = max($maxNum, (int) $m[1]);
            }
        }

        if (empty($_FILES['images'])) {
            jsonResponse(['error' => 'Geen afbeeldingen ontvangen'], 400);
        }

        $files = $_FILES['images'];
        $results = [];

        $count = is_array($files['name']) ? count($files['name']) : 1;
        for ($i = 0; $i < $count; $i++) {
            $tmpName = is_array($files['tmp_name']) ? $files['tmp_name'][$i] : $files['tmp_name'];
            $origName = is_array($files['name']) ? $files['name'][$i] : $files['name'];
            $error = is_array($files['error']) ? $files['error'][$i] : $files['error'];

            if ($error !== UPLOAD_ERR_OK) {
                $results[] = ['error' => "Upload mislukt voor $origName (code $error)"];
                continue;
            }

            $info = getimagesize($tmpName);
            if (!$info || !in_array($info[2], [IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_WEBP, IMAGETYPE_GIF], true)) {
                $results[] = ['error' => "$origName is geen geldig afbeeldingsformaat"];
                continue;
            }

            $maxNum++;
            $num = $maxNum;
            $fullPath = $picturesDir . "/foto{$num}.jpeg";
            $thumbPath = $picturesDir . "/foto{$num}_thumb.jpeg";

            $src = loadImage($tmpName, $info[2]);
            if (!$src) {
                $results[] = ['error' => "Kan $origName niet laden"];
                continue;
            }

            $origW = imagesx($src);
            $origH = imagesy($src);

            $fullW = 1600;
            $fullH = (int) round($origH * ($fullW / $origW));
            $fullImg = imagecreatetruecolor($fullW, $fullH);
            imagecopyresampled($fullImg, $src, 0, 0, 0, 0, $fullW, $fullH, $origW, $origH);
            imagejpeg($fullImg, $fullPath, 90);
            imagedestroy($fullImg);

            $thumbW = 400;
            $thumbH = 300;

            if ($origW / $origH >= $thumbW / $thumbH) {
                $resizeH = $thumbH;
                $resizeW = (int) round($origW * ($thumbH / $origH));
            } else {
                $resizeW = $thumbW;
                $resizeH = (int) round($origH * ($thumbW / $origW));
            }

            $resized = imagecreatetruecolor($resizeW, $resizeH);
            imagecopyresampled($resized, $src, 0, 0, 0, 0, $resizeW, $resizeH, $origW, $origH);

            $cropX = (int) round(($resizeW - $thumbW) / 2);
            $cropY = (int) round(($resizeH - $thumbH) / 2);

            $thumbImg = imagecreatetruecolor($thumbW, $thumbH);
            imagecopy($thumbImg, $resized, 0, 0, $cropX, $cropY, $thumbW, $thumbH);
            imagejpeg($thumbImg, $thumbPath, 85);
            imagedestroy($resized);
            imagedestroy($thumbImg);
            imagedestroy($src);

            $results[] = [
                'thumb' => "pictures/foto{$num}_thumb.jpeg",
                'full' => "pictures/foto{$num}.jpeg",
                'num' => $num,
            ];

            auditLog($user, 'upload_image', "folder=$concertFolder file=foto{$num}.jpeg original=\"$origName\"");
        }

        jsonResponse(['ok' => true, 'images' => $results]);
        break;

    default:
        jsonResponse(['error' => 'Onbekende actie'], 400);
}

function loadImage(string $path, int $type): ?GdImage {
    $img = match ($type) {
        IMAGETYPE_JPEG => imagecreatefromjpeg($path),
        IMAGETYPE_PNG => imagecreatefrompng($path),
        IMAGETYPE_WEBP => imagecreatefromwebp($path),
        IMAGETYPE_GIF => imagecreatefromgif($path),
        default => null,
    } ?: null;

    if ($img) {
        $img = fixExifOrientation($img, $path, $type);
    }
    return $img;
}

function fixExifOrientation(GdImage $img, string $path, int $type): GdImage {
    if ($type !== IMAGETYPE_JPEG || !function_exists('exif_read_data')) {
        return $img;
    }

    $exif = @exif_read_data($path);
    if (!$exif || empty($exif['Orientation'])) {
        return $img;
    }

    switch ((int) $exif['Orientation']) {
        case 2: imageflip($img, IMG_FLIP_HORIZONTAL); break;
        case 3: $img = imagerotate($img, 180, 0); break;
        case 4: imageflip($img, IMG_FLIP_VERTICAL); break;
        case 5: $img = imagerotate($img, -90, 0); imageflip($img, IMG_FLIP_HORIZONTAL); break;
        case 6: $img = imagerotate($img, -90, 0); break;
        case 7: $img = imagerotate($img, 90, 0); imageflip($img, IMG_FLIP_HORIZONTAL); break;
        case 8: $img = imagerotate($img, 90, 0); break;
    }

    return $img;
}
