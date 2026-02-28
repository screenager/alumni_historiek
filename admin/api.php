<?php
/**
 * Admin API for concertData.json
 * Handles authentication, CRUD operations, and audit logging.
 * Security: CSRF tokens, login rate limiting, secure sessions.
 */

// ── Secure session configuration ────────────────────────
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');
// Enable secure cookies when served over HTTPS
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', '1');
}

session_start();

// Paths
define('PASSWD_FILE',     __DIR__ . '/../private/passwd');
define('AUDIT_LOG',       __DIR__ . '/../private/audit.log');
define('RATE_LIMIT_FILE', __DIR__ . '/../private/rate_limits.json');
define('DATA_FILE',       __DIR__ . '/../concertData.json');
define('CONCERTS_DIR',    __DIR__ . '/../concerts');

// Rate limiting config
define('MAX_LOGIN_ATTEMPTS', 5);
define('RATE_LIMIT_WINDOW',  900); // 15 minutes

// ── Helpers ──────────────────────────────────────────────

function loadPasswd(): array {
    $users = [];
    foreach (file(PASSWD_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        [$user, $hash] = explode(':', $line, 2);
        $users[trim($user)] = trim($hash);
    }
    return $users;
}

function auditLog(string $user, string $action, string $detail = ''): void {
    $ts   = date('Y-m-d H:i:s');
    $ip   = $_SERVER['REMOTE_ADDR'] ?? 'cli';
    $line = "[$ts] user=$user ip=$ip action=$action $detail\n";
    file_put_contents(AUDIT_LOG, $line, FILE_APPEND | LOCK_EX);
}

function jsonResponse(array $data, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

function requireAuth(): string {
    if (empty($_SESSION['admin_user'])) {
        jsonResponse(['error' => 'Niet ingelogd'], 401);
    }
    return $_SESSION['admin_user'];
}

function loadConcerts(): array {
    $raw = file_get_contents(DATA_FILE);
    return json_decode($raw, true) ?? [];
}

function saveConcerts(array $concerts): void {
    $json = json_encode($concerts, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);

    // Compact image objects onto single lines to match original format:
    //   { "thumb": "...", "full": "..." }
    $json = preg_replace_callback(
        '/\{\s*"thumb":\s*"([^"]*)",\s*"full":\s*"([^"]*)"\s*\}/s',
        fn($m) => '{ "thumb": "' . $m[1] . '", "full": "' . $m[2] . '" }',
        $json
    );

    // Ensure trailing newline
    $json = rtrim($json) . "\n";

    file_put_contents(DATA_FILE, $json, LOCK_EX);
}

// ── CSRF protection ─────────────────────────────────────

function generateCsrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrfToken(): void {
    // Check header first (JSON requests), then POST field (multipart/form uploads)
    $token = $_SERVER['HTTP_X_CSRF_TOKEN']
          ?? $_POST['csrf_token']
          ?? '';

    if (empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        jsonResponse(['error' => 'Ongeldige CSRF-token — herlaad de pagina'], 403);
    }
}

function requireCsrf(): void {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrfToken();
    }
}

// ── Login rate limiting (file-based, per IP) ────────────

function getRateLimits(): array {
    if (!file_exists(RATE_LIMIT_FILE)) return [];
    $data = json_decode(file_get_contents(RATE_LIMIT_FILE), true);
    return is_array($data) ? $data : [];
}

function saveRateLimits(array $data): void {
    file_put_contents(RATE_LIMIT_FILE, json_encode($data), LOCK_EX);
}

function checkRateLimit(string $ip): void {
    $limits = getRateLimits();
    $now = time();

    // Clean expired entries
    foreach ($limits as $k => $entry) {
        if ($now - $entry['first'] > RATE_LIMIT_WINDOW) {
            unset($limits[$k]);
        }
    }
    saveRateLimits($limits);

    if (isset($limits[$ip]) && $limits[$ip]['count'] >= MAX_LOGIN_ATTEMPTS) {
        $remaining = RATE_LIMIT_WINDOW - ($now - $limits[$ip]['first']);
        auditLog('(rate_limited)', 'login_blocked', "ip=$ip remaining={$remaining}s");
        jsonResponse(['error' => "Te veel pogingen. Probeer opnieuw over " . ceil($remaining / 60) . " minuten."], 429);
    }
}

function recordFailedLogin(string $ip): void {
    $limits = getRateLimits();
    $now = time();
    if (!isset($limits[$ip]) || ($now - $limits[$ip]['first']) > RATE_LIMIT_WINDOW) {
        $limits[$ip] = ['count' => 1, 'first' => $now];
    } else {
        $limits[$ip]['count']++;
    }
    saveRateLimits($limits);
}

function clearRateLimit(string $ip): void {
    $limits = getRateLimits();
    unset($limits[$ip]);
    saveRateLimits($limits);
}

// ── Route dispatcher ────────────────────────────────────

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';

// CORS-friendly for same-origin; needed when using fetch()
header('X-Content-Type-Options: nosniff');

switch ($action) {

    // ── LOGIN ────────────────────────────────────────────
    case 'login':
        if ($method !== 'POST') jsonResponse(['error' => 'POST vereist'], 405);

        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        checkRateLimit($ip);

        $input = json_decode(file_get_contents('php://input'), true);
        $username = trim($input['username'] ?? '');
        $password = $input['password'] ?? '';

        $users = loadPasswd();
        if (!isset($users[$username]) || !password_verify($password, $users[$username])) {
            recordFailedLogin($ip);
            auditLog($username ?: '(unknown)', 'login_failed');
            jsonResponse(['error' => 'Ongeldige gebruikersnaam of wachtwoord'], 401);
        }

        clearRateLimit($ip);
        session_regenerate_id(true);
        $_SESSION['admin_user'] = $username;
        $token = generateCsrfToken();
        auditLog($username, 'login_success');
        jsonResponse(['ok' => true, 'user' => $username, 'csrf_token' => $token]);
        break;

    // ── LOGOUT ───────────────────────────────────────────
    case 'logout':
        $user = $_SESSION['admin_user'] ?? '(unknown)';
        auditLog($user, 'logout');
        session_destroy();
        jsonResponse(['ok' => true]);
        break;

    // ── SESSION STATUS ───────────────────────────────────
    case 'status':
        if (!empty($_SESSION['admin_user'])) {
            $token = generateCsrfToken();
            jsonResponse(['loggedIn' => true, 'user' => $_SESSION['admin_user'], 'csrf_token' => $token]);
        } else {
            jsonResponse(['loggedIn' => false]);
        }
        break;

    // ── LIST CONCERTS ────────────────────────────────────
    case 'list':
        requireAuth();
        jsonResponse(loadConcerts());
        break;

    // ── GET SINGLE CONCERT ───────────────────────────────
    case 'get':
        requireAuth();
        $index = $_GET['index'] ?? null;
        if ($index === null) jsonResponse(['error' => 'Index ontbreekt'], 400);
        $concerts = loadConcerts();
        if (!isset($concerts[(int)$index])) jsonResponse(['error' => 'Concert niet gevonden'], 404);
        jsonResponse($concerts[(int)$index]);
        break;

    // ── UPDATE CONCERT ───────────────────────────────────
    case 'update':
        if ($method !== 'POST') jsonResponse(['error' => 'POST vereist'], 405);
        $user = requireAuth();
        requireCsrf();

        $input = json_decode(file_get_contents('php://input'), true);
        $index = $input['index'] ?? null;
        $data  = $input['data']  ?? null;

        if ($index === null || $data === null) {
            jsonResponse(['error' => 'index en data vereist'], 400);
        }

        $concerts = loadConcerts();
        if (!isset($concerts[(int)$index])) {
            jsonResponse(['error' => 'Concert niet gevonden'], 404);
        }

        $oldTitle = $concerts[(int)$index]['title'] ?? '(onbekend)';
        $oldConcert = $concerts[(int)$index];

        // Preserve original key order: update existing keys in-place,
        // only add new keys if they have a non-empty value.
        $original = $concerts[(int)$index];
        foreach ($data as $key => $value) {
            if (array_key_exists($key, $original) || ($value !== '' && $value !== null)) {
                $original[$key] = $value;
            }
        }
        // Remove keys deleted from the form (keep 'images' always)
        foreach (array_keys($original) as $key) {
            if ($key !== 'images' && !array_key_exists($key, $data)) {
                unset($original[$key]);
            }
        }

        // Delete removed image files from disk
        $oldImages = $oldConcert['images'] ?? [];
        $newImages = $data['images'] ?? [];
        $newPaths  = array_merge(
            array_column($newImages, 'thumb'),
            array_column($newImages, 'full')
        );
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

        // Delete poster file if postcard_img was cleared
        $oldPoster = $oldConcert['postcard_img'] ?? '';
        $newPoster = $data['postcard_img'] ?? '';
        if ($oldPoster && !$newPoster) {
            $posterPath = CONCERTS_DIR . '/' . $oldPoster;
            if (file_exists($posterPath)) {
                unlink($posterPath);
                auditLog($user, 'delete_poster', "file=$oldPoster");
            }
        }

        $concerts[(int)$index] = $original;
        saveConcerts($concerts);

        auditLog($user, 'update_concert', "index=$index title=\"{$data['title']}\" (was \"$oldTitle\")");
        jsonResponse(['ok' => true]);
        break;

    // ── ADD CONCERT ──────────────────────────────────────
    case 'add':
        if ($method !== 'POST') jsonResponse(['error' => 'POST vereist'], 405);
        $user = requireAuth();
        requireCsrf();

        $data = json_decode(file_get_contents('php://input'), true);
        if (!$data) jsonResponse(['error' => 'Ongeldige data'], 400);

        $concerts   = loadConcerts();
        $concerts[] = $data;
        saveConcerts($concerts);

        $newIndex = count($concerts) - 1;
        auditLog($user, 'add_concert', "index=$newIndex title=\"{$data['title']}\"");
        jsonResponse(['ok' => true, 'index' => $newIndex]);
        break;

    // ── DELETE CONCERT ───────────────────────────────────
    case 'delete':
        if ($method !== 'POST') jsonResponse(['error' => 'POST vereist'], 405);
        $user = requireAuth();
        requireCsrf();

        $input = json_decode(file_get_contents('php://input'), true);
        $index = $input['index'] ?? null;
        if ($index === null) jsonResponse(['error' => 'index vereist'], 400);

        $concerts = loadConcerts();
        if (!isset($concerts[(int)$index])) {
            jsonResponse(['error' => 'Concert niet gevonden'], 404);
        }

        $concert = $concerts[(int)$index];
        $title = $concert['title'] ?? '(onbekend)';

        // Delete associated image files from disk
        $concertFolder = ($concert['year'] ?? '') . '_' . ($concert['slug'] ?? '');
        if ($concertFolder !== '_') {
            foreach ($concert['images'] ?? [] as $img) {
                foreach (['thumb', 'full'] as $k) {
                    $rel = $img[$k] ?? '';
                    if ($rel) {
                        $absPath = CONCERTS_DIR . '/' . $concertFolder . '/' . $rel;
                        if (file_exists($absPath)) {
                            unlink($absPath);
                        }
                    }
                }
            }
            // Delete poster
            $poster = $concert['postcard_img'] ?? '';
            if ($poster) {
                $posterPath = CONCERTS_DIR . '/' . $poster;
                if (file_exists($posterPath)) {
                    unlink($posterPath);
                }
            }
        }

        array_splice($concerts, (int)$index, 1);
        saveConcerts($concerts);

        auditLog($user, 'delete_concert', "index=$index title=\"$title\"");
        jsonResponse(['ok' => true]);
        break;

    // ── UPLOAD POSTER ────────────────────────────────────
    case 'upload_poster':
        if ($method !== 'POST') jsonResponse(['error' => 'POST vereist'], 405);
        $user = requireAuth();
        requireCsrf();

        $concertFolder = $_POST['folder'] ?? '';
        if (!$concertFolder || !preg_match('/^[a-z0-9_]+$/i', $concertFolder)) {
            jsonResponse(['error' => 'Ongeldige concertmap'], 400);
        }

        $concertDir = CONCERTS_DIR . '/' . $concertFolder;
        if (!is_dir($concertDir)) {
            mkdir($concertDir, 0755, true);
        }

        if (empty($_FILES['poster']) || $_FILES['poster']['error'] !== UPLOAD_ERR_OK) {
            $code = $_FILES['poster']['error'] ?? 'geen bestand';
            jsonResponse(['error' => "Upload mislukt (code $code)"], 400);
        }

        $tmpName = $_FILES['poster']['tmp_name'];
        $origName = $_FILES['poster']['name'];
        $info = getimagesize($tmpName);
        if (!$info || !in_array($info[2], [IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_WEBP, IMAGETYPE_GIF])) {
            jsonResponse(['error' => 'Geen geldig afbeeldingsformaat'], 400);
        }

        $src = loadImage($tmpName, $info[2]);
        if (!$src) {
            jsonResponse(['error' => 'Kan afbeelding niet laden'], 500);
        }

        $origW = imagesx($src);
        $origH = imagesy($src);

        // Resize to 1200px height, maintain aspect ratio
        $targetH = 1200;
        $targetW = (int)round($origW * ($targetH / $origH));

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
            'height' => $targetH
        ]);
        break;

    // ── UPLOAD IMAGES ────────────────────────────────────
    case 'upload':
        if ($method !== 'POST') jsonResponse(['error' => 'POST vereist'], 405);
        $user = requireAuth();
        requireCsrf();

        $concertFolder = $_POST['folder'] ?? '';
        if (!$concertFolder || !preg_match('/^[a-z0-9_]+$/i', $concertFolder)) {
            jsonResponse(['error' => 'Ongeldige concertmap'], 400);
        }

        $picturesDir = CONCERTS_DIR . '/' . $concertFolder . '/pictures';
        if (!is_dir($picturesDir)) {
            mkdir($picturesDir, 0755, true);
        }

        // Determine next foto number
        $existing = glob($picturesDir . '/foto*.jpeg');
        $maxNum = 0;
        foreach ($existing as $f) {
            if (preg_match('/foto(\d+)(?:_thumb)?\.jpeg$/', basename($f), $m)) {
                $maxNum = max($maxNum, (int)$m[1]);
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
            $error   = is_array($files['error']) ? $files['error'][$i] : $files['error'];

            if ($error !== UPLOAD_ERR_OK) {
                $results[] = ['error' => "Upload mislukt voor $origName (code $error)"];
                continue;
            }

            // Validate is image
            $info = getimagesize($tmpName);
            if (!$info || !in_array($info[2], [IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_WEBP, IMAGETYPE_GIF])) {
                $results[] = ['error' => "$origName is geen geldig afbeeldingsformaat"];
                continue;
            }

            $maxNum++;
            $num = $maxNum;
            $fullPath  = $picturesDir . "/foto{$num}.jpeg";
            $thumbPath = $picturesDir . "/foto{$num}_thumb.jpeg";

            // Load source image
            $src = loadImage($tmpName, $info[2]);
            if (!$src) {
                $results[] = ['error' => "Kan $origName niet laden"];
                continue;
            }

            $origW = imagesx($src);
            $origH = imagesy($src);

            // ── Create full-size (1600px wide) ──
            $fullW = 1600;
            $fullH = (int)round($origH * ($fullW / $origW));
            $fullImg = imagecreatetruecolor($fullW, $fullH);
            imagecopyresampled($fullImg, $src, 0, 0, 0, 0, $fullW, $fullH, $origW, $origH);
            imagejpeg($fullImg, $fullPath, 90);
            imagedestroy($fullImg);

            // ── Create thumbnail (400×300, center-cropped) ──
            $thumbW = 400;
            $thumbH = 300;

            if ($origW / $origH >= $thumbW / $thumbH) {
                // Landscape or wider: resize so height = 300, then crop width
                $resizeH = $thumbH;
                $resizeW = (int)round($origW * ($thumbH / $origH));
            } else {
                // Portrait or taller: resize so width = 400, then crop height
                $resizeW = $thumbW;
                $resizeH = (int)round($origH * ($thumbW / $origW));
            }

            $resized = imagecreatetruecolor($resizeW, $resizeH);
            imagecopyresampled($resized, $src, 0, 0, 0, 0, $resizeW, $resizeH, $origW, $origH);

            // Center crop to 400×300
            $cropX = (int)round(($resizeW - $thumbW) / 2);
            $cropY = (int)round(($resizeH - $thumbH) / 2);

            $thumbImg = imagecreatetruecolor($thumbW, $thumbH);
            imagecopy($thumbImg, $resized, 0, 0, $cropX, $cropY, $thumbW, $thumbH);
            imagejpeg($thumbImg, $thumbPath, 85);
            imagedestroy($resized);
            imagedestroy($thumbImg);
            imagedestroy($src);

            $results[] = [
                'thumb' => "pictures/foto{$num}_thumb.jpeg",
                'full'  => "pictures/foto{$num}.jpeg",
                'num'   => $num
            ];

            auditLog($user, 'upload_image', "folder=$concertFolder file=foto{$num}.jpeg original=\"$origName\"");
        }

        jsonResponse(['ok' => true, 'images' => $results]);
        break;

    default:
        jsonResponse(['error' => 'Onbekende actie'], 400);
}

// ── Image loading helper ────────────────────────────────
function loadImage(string $path, int $type): ?GdImage {
    $img = match ($type) {
        IMAGETYPE_JPEG => imagecreatefromjpeg($path),
        IMAGETYPE_PNG  => imagecreatefrompng($path),
        IMAGETYPE_WEBP => imagecreatefromwebp($path),
        IMAGETYPE_GIF  => imagecreatefromgif($path),
        default        => null,
    } ?: null;

    if ($img) {
        $img = fixExifOrientation($img, $path, $type);
    }
    return $img;
}

/**
 * Read EXIF orientation tag and rotate/flip the image so it
 * displays correctly regardless of camera orientation metadata.
 */
function fixExifOrientation(GdImage $img, string $path, int $type): GdImage {
    // EXIF data is only embedded in JPEG files
    if ($type !== IMAGETYPE_JPEG || !function_exists('exif_read_data')) {
        return $img;
    }
    $exif = @exif_read_data($path);
    if (!$exif || empty($exif['Orientation'])) {
        return $img;
    }
    switch ((int)$exif['Orientation']) {
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
