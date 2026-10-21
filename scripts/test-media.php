<?php

// Run with: php scripts/test-media.php
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit;
}

define('ABSPATH', __DIR__ . '/../');
define('ALUMNI_HISTORIEK_PLUGIN_URL', 'https://alumniarenbergorkest.be/wp-content/plugins/alumni-historiek/');

class WP_Error {
    private $message;

    public function __construct(string $code, string $message) {
        $this->message = $message;
    }

    public function get_error_message(): string {
        return $this->message;
    }
}

function is_wp_error($value): bool { return $value instanceof WP_Error; }
function add_action(...$args): void {}
function wp_get_ext_types(): array {
    return ['image' => ['jpg', 'jpeg', 'png', 'gif', 'webp'], 'video' => ['mp4', 'mov', 'webm', 'ogv', 'm4v']];
}
function number_format_i18n(float $value, int $decimals): string { return number_format($value, $decimals); }
function current_user_can(string $capability): bool { return $GLOBALS['allowed']; }
function wp_die(string $message): void { throw new RuntimeException($message); }
function wp_unslash($value) {
    return is_array($value) ? array_map('wp_unslash', $value) : stripslashes($value);
}
function check_admin_referer(string $action): void {
    if (($GLOBALS['valid_nonce'] ?? '') !== $action) {
        wp_die('Invalid nonce');
    }
}
function alumni_historiek_storage_info(): array { return $GLOBALS['storage']; }
function admin_url(string $path): string { return '/wp-admin/' . $path; }
function esc_html(string $value): string { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }
function esc_attr(string $value): string { return esc_html($value); }
function esc_url(string $value): string { return esc_html($value); }
function add_query_arg(string $key, string $value, string $url): string { return $url . '&' . $key . '=' . rawurlencode($value); }
function wp_nonce_field(string $action): void { echo '<input name="_wpnonce" value="' . esc_attr($action) . '">'; }

require __DIR__ . '/../admin/media.php';

$checks = 0;
function verify(bool $condition, string $message): void {
    global $checks;
    $checks++;
    if (!$condition) {
        throw new RuntimeException($message);
    }
}
function expect_failure(callable $action, string $message): void {
    try {
        $action();
    } catch (RuntimeException $error) {
        verify(strpos($error->getMessage(), $message) !== false, 'Unexpected failure: ' . $error->getMessage());
        return;
    }
    verify(false, 'Expected failure: ' . $message);
}

function media_fails(callable $action): bool {
    try {
        $action();
    } catch (RuntimeException $error) {
        return true;
    }
    return false;
}

$temporary = sys_get_temp_dir() . '/historiek-media-' . bin2hex(random_bytes(8));
mkdir($temporary);
$storage = ['mode' => 'plugin', 'base_url' => 'https://alumniarenbergorkest.be/wp-content/plugins/alumni-historiek', 'data_file' => $temporary . '/concertData.json', 'concerts_dir' => $temporary . '/concerts'];
$GLOBALS['storage'] = $storage;
$GLOBALS['allowed'] = true;
mkdir($storage['concerts_dir']);
mkdir($storage['concerts_dir'] . '/2026_test');
mkdir($storage['concerts_dir'] . '/2026_test/pictures');
mkdir($storage['concerts_dir'] . '/2026_test/videos');
$concert = [
    'postcard_img' => '2026_test/poster.jpg',
    'images' => [
        ['thumb' => 'pictures/one_thumb.jpeg', 'full' => 'pictures/one.jpeg'],
        'pictures/two.jpeg',
        ['thumb' => 'pictures/three.jpeg', 'full' => 'pictures/three.jpeg'],
        ['thumb' => 'pictures/four.jpeg', 'full' => 'pictures/four.jpeg'],
        ['thumb' => 'pictures/hidden.jpeg', 'full' => 'pictures/hidden.jpeg'],
    ],
    'videos' => [
        ['src' => 'videos/one.mp4', 'poster' => 'videos/one_poster.jpg'],
        ['file' => 'videos/two.mov', 'poster' => 'videos/two_poster.jpg'],
        'videos/three.webm',
    ],
];
$save = static function ($data) use ($storage): void {
    file_put_contents($storage['data_file'], json_encode($data));
};
$save(['concerts' => [$concert]]);
foreach ([
    'poster.jpg', 'pictures/one_thumb.jpeg', 'pictures/one.jpeg', 'pictures/two.jpeg',
    'pictures/three.jpeg', 'pictures/four.jpeg', 'pictures/hidden.jpeg',
    'videos/one.mp4', 'videos/one_poster.jpg', 'videos/two.mov', 'videos/two_poster.jpg',
    'videos/three.webm', 'orphan.JPG', 'original_poster.png', '.DS_Store', 'code.php',
] as $path) {
    file_put_contents($storage['concerts_dir'] . '/2026_test/' . $path, 'test media');
}
file_put_contents($temporary . '/outside.jpg', 'outside');
symlink($temporary . '/outside.jpg', $storage['concerts_dir'] . '/outside.jpg');
symlink($temporary, $storage['concerts_dir'] . '/outside-directory');

try {
    foreach ([
        '../concerts',
        'http://localhost/alumni_historiek/concerts',
        'http://localhost/wp-content/plugins/alumni-historiek/concerts',
        'https://alumniarenbergorkest.be/wp-content/plugins/alumni-historiek/concerts',
        'https://alumniarenbergorkest.be/wp-content/uploads/alumni-historiek/concerts',
    ] as $base) {
        verify(alumni_historiek_media_url($base . '/', '2026_test/foto #1%+.jpg') === $base . '/2026_test/foto%20%231%25%2B.jpg', 'Media URLs preserve deployment base and encode filename segments.');
    }
    $files = alumni_historiek_media_inventory($storage);
    verify(is_array($files) && count($files) === 14, 'Inventory includes only image/video files, never symlinks.');
    foreach (['poster.jpg', 'pictures/one_thumb.jpeg', 'pictures/one.jpeg', 'pictures/four.jpeg', 'videos/two.mov', 'videos/two_poster.jpg', 'videos/three.webm'] as $path) {
        verify($files['2026_test/' . $path]['visible'], 'Card/lightbox media must be visible: ' . $path);
    }
    verify(!$files['2026_test/pictures/hidden.jpeg']['visible'] && $files['2026_test/pictures/hidden.jpeg']['referenced'], 'Images after slot four are referenced but not visible.');
    verify(!$files['2026_test/orphan.JPG']['referenced'], 'Unreferenced media is orphaned.');
    verify($files['2026_test/orphan.JPG']['extension'] === 'jpg', 'Extensions are case-insensitive.');
    verify($files['2026_test/orphan.JPG']['size'] === 10, 'Inventory reports exact byte size.');
    verify(alumni_historiek_media_size(1024) === '1.00 KB', 'KB formatting.');
    verify(alumni_historiek_media_size(1048575) === '1,024.00 KB', 'Values below MB boundary remain KB.');
    verify(alumni_historiek_media_size(1048576) === '1.00 MB', 'MB boundary formatting.');

    ob_start();
    alumni_historiek_render_media_screen();
    $html = ob_get_clean();
    verify(strpos($html, 'Nee - wel gekoppeld') !== false && strpos($html, 'Nee - verweesd') !== false, 'Table distinguishes hidden references and orphans.');
    verify(substr_count($html, '>Verwijderen</a>') === 2, 'Only two orphaned files offer deletion.');
    verify(strpos($html, 'scope="col"') !== false && strpos($html, 'overflow-x:auto') !== false, 'Accessible table supports mobile scrolling.');
    verify(substr_count($html, 'name="files[]"') === 2, 'WordPress bulk selection is available only for orphans.');
    verify(substr_count($html, 'data-media-sort=') === 5, 'All five WordPress data columns support sorting.');
    verify(strpos($html, 'href="' . $storage['base_url'] . '/concerts/2026_test/poster.jpg" target="_blank" rel="noopener noreferrer"') !== false, 'WordPress filenames link to active plugin storage.');
    $GLOBALS['storage']['base_url'] = 'https://alumniarenbergorkest.be/wp-content/uploads/alumni-historiek';
    ob_start();
    alumni_historiek_render_media_screen();
    $uploads_html = ob_get_clean();
    verify(strpos($uploads_html, 'href="https://alumniarenbergorkest.be/wp-content/uploads/alumni-historiek/concerts/2026_test/poster.jpg"') !== false, 'WordPress filenames use uploads URLs when active.');
    $GLOBALS['storage'] = $storage;
    $_GET['file'] = '2026_test/orphan.JPG';
    ob_start();
    alumni_historiek_render_media_screen();
    $html = ob_get_clean();
    verify(strpos($html, 'method="post"') !== false && strpos($html, 'Definitief verwijderen') !== false, 'Deletion link opens a POST confirmation.');
    verify(is_file($storage['concerts_dir'] . '/2026_test/orphan.JPG'), 'Opening confirmation does not delete.');
    $_GET = [];
    file_put_contents($storage['concerts_dir'] . '/2026_test/<orphan>.jpg', 'image');
    ob_start();
    alumni_historiek_render_media_screen();
    $html = ob_get_clean();
    verify(strpos($html, '&lt;orphan&gt;.jpg') !== false && strpos($html, '<orphan>') === false, 'Filenames are escaped in table output.');
    unlink($storage['concerts_dir'] . '/2026_test/<orphan>.jpg');

    foreach (['2026_test/poster.jpg', '2026_test/pictures/hidden.jpeg', '../outside.jpg', 'outside.jpg', 'outside-directory/outside.jpg', '2026_test/code.php'] as $path) {
        verify(media_fails(fn() => alumni_historiek_delete_orphaned_media($storage, $path)), 'Reject unsafe or referenced deletion: ' . $path);
    }
    $changed = $concert;
    $changed['images'][] = 'orphan.JPG';
    $save(['concerts' => [$changed]]);
    verify(media_fails(fn() => alumni_historiek_delete_orphaned_media($storage, '2026_test/orphan.JPG')), 'Recheck references after listing.');
    $save(['concerts' => [$concert]]);
    verify(media_fails(fn() => alumni_historiek_delete_media_batch($storage, [])), 'Empty bulk selection is rejected.');
    verify(media_fails(fn() => alumni_historiek_delete_media_batch($storage, [12])), 'Invalid bulk paths are rejected.');
    verify(media_fails(fn() => alumni_historiek_delete_media_batch($storage, ['2026_test/orphan.JPG', '2026_test/poster.jpg'])), 'Mixed bulk selection is rejected before deletion.');
    verify(is_file($storage['concerts_dir'] . '/2026_test/orphan.JPG'), 'Invalid bulk selection does not delete the valid orphan.');
    file_put_contents($storage['concerts_dir'] . '/2026_test/bulk1.jpg', 'orphan');
    file_put_contents($storage['concerts_dir'] . '/2026_test/bulk2.jpg', 'orphan');
    $batch = alumni_historiek_delete_media_batch($storage, ['2026_test/bulk1.jpg', '2026_test/bulk2.jpg', '2026_test/bulk1.jpg']);
    verify(count($batch['deleted']) === 2 && !$batch['errors'], 'Bulk deletion removes unique orphan paths.');
    verify(!file_exists($storage['concerts_dir'] . '/2026_test/bulk1.jpg') && !file_exists($storage['concerts_dir'] . '/2026_test/bulk2.jpg'), 'Both bulk orphans are removed.');
    verify(alumni_historiek_delete_orphaned_media($storage, '2026_test/orphan.JPG') === true, 'Delete a real orphan.');
    verify(!file_exists($storage['concerts_dir'] . '/2026_test/orphan.JPG'), 'Orphan was removed from disk.');
    verify(is_file($temporary . '/outside.jpg'), 'Outside files remain intact.');

    foreach (['{', '{}', '{"header":{}}', '{"concerts":null}', '{"concerts":{}}', '{"concerts":[null]}', '{"concerts":[{"images":false}]}', '{"concerts":[{"postcard_img":12}]}'] as $invalid) {
        file_put_contents($storage['data_file'], $invalid);
        verify(media_fails(fn() => alumni_historiek_delete_orphaned_media($storage, '2026_test/original_poster.png')), 'Invalid data must block deletion: ' . $invalid);
    }
    $save([$concert]);
    verify(is_array(alumni_historiek_media_inventory($storage)), 'Legacy array data remains supported.');
    $save(['concerts' => []]);
    verify(is_array(alumni_historiek_media_inventory($storage)), 'An explicitly empty concert list is valid.');
    $save(['concerts' => [$concert]]);
    unlink($storage['data_file']);
    verify(media_fails(fn() => alumni_historiek_delete_orphaned_media($storage, '2026_test/original_poster.png')), 'Missing data must block deletion.');
    $save(['concerts' => [$concert]]);

    $references = alumni_historiek_media_references([['postcard_img' => '2026_test/poster.jpg', 'images' => ['pictures/./one%20photo.jpeg?ver=1#image']]]);
    verify(isset($references['2026_test/pictures/one photo.jpeg']), 'Browser path normalization handles encoded names, query strings and dot segments.');
    symlink($storage['concerts_dir'] . '/2026_test/original_poster.png', $storage['concerts_dir'] . '/alias.png');
    $save(['concerts' => [['postcard_img' => 'alias.png']]]);
    verify(media_fails(fn() => alumni_historiek_delete_orphaned_media($storage, '2026_test/original_poster.png')), 'References through symlinks protect their real target.');

    $GLOBALS['allowed'] = false;
    expect_failure('alumni_historiek_delete_media', 'geen rechten');
    expect_failure('alumni_historiek_delete_media_bulk', 'geen rechten');
    expect_failure('alumni_historiek_render_media_screen', 'geen rechten');
    $GLOBALS['allowed'] = true;
    $_SERVER['REQUEST_METHOD'] = 'GET';
    expect_failure('alumni_historiek_delete_media', 'POST vereist');
    expect_failure('alumni_historiek_delete_media_bulk', 'POST vereist');
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_POST = ['file' => '2026_test/original_poster.png', 'storage_mode' => 'plugin'];
    expect_failure('alumni_historiek_delete_media', 'Invalid nonce');
    expect_failure('alumni_historiek_delete_media_bulk', 'Invalid nonce');
    $_POST['storage_mode'] = 'uploads';
    $GLOBALS['valid_nonce'] = 'alumni_historiek_delete_media|uploads|2026_test/original_poster.png';
    expect_failure('alumni_historiek_delete_media', 'opslaglocatie is gewijzigd');
    $GLOBALS['valid_nonce'] = 'alumni_historiek_delete_media_bulk|uploads';
    expect_failure('alumni_historiek_delete_media_bulk', 'opslaglocatie is gewijzigd');
    $_POST = ['storage_mode' => 'plugin', 'files' => ['2026_test/poster.jpg']];
    $GLOBALS['valid_nonce'] = 'alumni_historiek_delete_media_bulk|plugin';
    $save(['concerts' => [$concert]]);
    expect_failure('alumni_historiek_delete_media_bulk', 'gekoppeld bestand');

    $storage['mode'] = 'uploads';
    verify(is_array(alumni_historiek_media_inventory($storage)), 'Uploads storage uses the same inventory logic.');
    $missing = $storage;
    $missing['concerts_dir'] = $temporary . '/missing';
    verify(media_fails(fn() => alumni_historiek_media_inventory($missing)), 'Missing media directories report an error.');
    $linked = $storage;
    $linked['concerts_dir'] = $storage['concerts_dir'] . '/outside-directory';
    verify(media_fails(fn() => alumni_historiek_media_inventory($linked)), 'Symlink media roots are rejected.');
    echo "OK: $checks media checks passed.\n";
} finally {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($temporary, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $entry) {
        if ($entry->isLink() || $entry->isFile()) {
            unlink($entry->getPathname());
        } else {
            rmdir($entry->getPathname());
        }
    }
    rmdir($temporary);
}
