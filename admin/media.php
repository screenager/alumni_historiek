<?php

if (!defined('ABSPATH') && !defined('ALUMNI_HISTORIEK_ADMIN_API')) {
    exit;
}

function alumni_historiek_media_path(string $path): string {
    $path = rawurldecode(explode('?', explode('#', $path, 2)[0], 2)[0]);
    $parts = [];
    foreach (explode('/', str_replace('\\', '/', $path)) as $part) {
        if ($part === '' || $part === '.') {
            continue;
        }
        if ($part === '..') {
            if (!$parts) {
                return '';
            }
            array_pop($parts);
        } else {
            $parts[] = $part;
        }
    }
    return implode('/', $parts);
}

function alumni_historiek_media_url(string $base_url, string $path): string {
    return rtrim($base_url, '/') . '/' . implode('/', array_map('rawurlencode', explode('/', $path)));
}

function alumni_historiek_media_references(array $concerts): array {
    $references = [];
    $add = static function ($path, string $prefix, bool $visible) use (&$references): void {
        if (!is_string($path)) {
            throw new UnexpectedValueException('Ongeldig mediapad in concertdata.');
        }
        if ($path === '') {
            return;
        }
        $key = alumni_historiek_media_path($prefix . $path);
        if ($key !== '') {
            $references[$key] = ($references[$key] ?? false) || $visible;
        }
    };

    foreach ($concerts as $concert) {
        if (!is_array($concert)) {
            throw new UnexpectedValueException('Ongeldig concert in concertdata.');
        }
        $poster = $concert['postcard_img'] ?? '';
        $add($poster, '', true);
        $prefix = is_string($poster) && $poster !== '' ? explode('/', $poster)[0] . '/' : '';
        $images = $concert['images'] ?? [];
        $videos = $concert['videos'] ?? [];
        if (!is_array($images) || !is_array($videos)) {
            throw new UnexpectedValueException('Ongeldige afbeeldingen of videos in concertdata.');
        }
        foreach (array_values($images) as $index => $image) {
            $visible = $index < 4;
            if (is_string($image)) {
                $add($image, $prefix, $visible);
            } elseif (is_array($image)) {
                $add($image['thumb'] ?? '', $prefix, $visible);
                $add($image['full'] ?? '', $prefix, $visible);
            } else {
                throw new UnexpectedValueException('Ongeldige afbeelding in concertdata.');
            }
        }
        foreach ($videos as $video) {
            if (is_string($video)) {
                $add($video, $prefix, true);
            } elseif (is_array($video)) {
                $add($video['src'] ?? $video['file'] ?? '', $prefix, true);
                $add($video['poster'] ?? '', $prefix, true);
            } else {
                throw new UnexpectedValueException('Ongeldige video in concertdata.');
            }
        }
        // Keep linked documents protected even though the current cards do not render them.
        $add($concert['pdf'] ?? '', '', false);
    }
    return $references;
}

function alumni_historiek_media_inventory(array $storage) {
    if (!is_readable($storage['data_file'])) {
        throw new RuntimeException('Concertdata kan niet worden gelezen. Verwijderen is uitgeschakeld.');
    }
    $json = file_get_contents($storage['data_file']);
    if ($json === false) {
        throw new RuntimeException('Concertdata kan niet worden gelezen. Verwijderen is uitgeschakeld.');
    }
    $data = json_decode($json, true);
    if (json_last_error() !== JSON_ERROR_NONE || !is_array($data)) {
        throw new RuntimeException('Concertdata is ongeldig. Verwijderen is uitgeschakeld.');
    }
    $structure = json_decode($json);
    if (!is_array($structure) && !(is_object($structure) && isset($structure->concerts) && is_array($structure->concerts))) {
        throw new RuntimeException('De concertlijst ontbreekt of is ongeldig. Verwijderen is uitgeschakeld.');
    }
    $concerts = array_key_exists('concerts', $data) ? $data['concerts'] : $data;
    if (!is_array($concerts) || array_values($concerts) !== $concerts) {
        throw new RuntimeException('De concertlijst is ongeldig. Verwijderen is uitgeschakeld.');
    }
    $root = realpath($storage['concerts_dir']);
    if ($root === false || !is_dir($root) || is_link($storage['concerts_dir'])) {
        throw new RuntimeException('De concertmap ontbreekt of is een symbolische link. Controleer de opslaginstellingen.');
    }
    $types = function_exists('wp_get_ext_types') ? wp_get_ext_types() : [
        'image' => ['jpg', 'jpeg', 'jpe', 'gif', 'png', 'bmp', 'tiff', 'tif', 'webp', 'avif', 'ico', 'heic', 'heif', 'heics', 'heifs'],
        'video' => ['asf', 'avi', 'divx', 'flv', 'mov', 'qt', 'mpeg', 'mpg', 'mpe', 'mp4', 'm4v', 'ogv', 'webm', 'mkv', '3gp', '3gpp', '3g2', '3gpp2', 'wmv'],
    ];
    $extensions = array_merge($types['image'], $types['video']);
    $files = [];
    try {
        $references = alumni_historiek_media_references($concerts);
        // A reference through a filesystem alias must also protect the real file.
        foreach ($references as $path => $visible) {
            $resolved = realpath($root . '/' . $path);
            if ($resolved !== false && strpos($resolved, $root . '/') === 0) {
                $key = substr($resolved, strlen($root) + 1);
                $references[$key] = ($references[$key] ?? false) || $visible;
            }
        }
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
        );
        foreach ($iterator as $file) {
            if ($file->isLink() || !$file->isFile()) {
                continue;
            }
            $extension = strtolower($file->getExtension());
            if (!in_array($extension, $extensions, true)) {
                continue;
            }
            $path = substr($file->getPathname(), strlen($root) + 1);
            $size = $file->getSize();
            if ($size === false) {
                throw new UnexpectedValueException('Bestandsgrootte kan niet worden gelezen: ' . $path);
            }
            $files[$path] = [
                'filename' => $path,
                'extension' => $extension,
                'size' => $size,
                'visible' => $references[$path] ?? false,
                'referenced' => array_key_exists($path, $references),
            ];
        }
    } catch (UnexpectedValueException $error) {
        throw new RuntimeException('Media controleren mislukt: ' . $error->getMessage(), 0, $error);
    } catch (RuntimeException $error) {
        throw new RuntimeException('Media lezen mislukt: ' . $error->getMessage(), 0, $error);
    }
    ksort($files, SORT_NATURAL | SORT_FLAG_CASE);
    return $files;
}

function alumni_historiek_delete_orphaned_media(array $storage, string $path) {
    $files = alumni_historiek_media_inventory($storage);
    if (!isset($files[$path])) {
        throw new RuntimeException('Het mediabestand bestaat niet of mag niet worden verwijderd.');
    }
    if ($files[$path]['referenced']) {
        throw new RuntimeException('Dit bestand is gekoppeld aan een concert en mag niet worden verwijderd.');
    }
    $root = realpath($storage['concerts_dir']);
    $target = $root . '/' . $path;
    clearstatcache(true, $target);
    if (is_link($target) || realpath($target) !== $target || !is_file($target)) {
        throw new RuntimeException('Het bestandspad is gewijzigd. Vernieuw de medialijst.');
    }
    if (!unlink($target)) {
        throw new RuntimeException('Het bestand kon niet worden verwijderd. Controleer de schrijfrechten.');
    }
    return true;
}

function alumni_historiek_delete_media(): void {
    if (!current_user_can('manage_options')) {
        wp_die('Je hebt geen rechten om deze actie uit te voeren.');
    }
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        wp_die('POST vereist.');
    }
    $path = isset($_POST['file']) && is_string($_POST['file']) ? wp_unslash($_POST['file']) : '';
    $mode = isset($_POST['storage_mode']) && is_string($_POST['storage_mode']) ? wp_unslash($_POST['storage_mode']) : '';
    check_admin_referer('alumni_historiek_delete_media|' . $mode . '|' . $path);
    $storage = alumni_historiek_storage_info();
    if ($mode !== $storage['mode']) {
        wp_die('De opslaglocatie is gewijzigd. Vernieuw de medialijst.');
    }
    try {
        alumni_historiek_delete_orphaned_media($storage, $path);
    } catch (RuntimeException $error) {
        wp_die(esc_html($error->getMessage()));
    }
    wp_safe_redirect(admin_url('admin.php?page=alumni-historiek-media&deleted=1'));
    exit;
}
if (defined('ABSPATH')) {
    add_action('admin_post_alumni_historiek_delete_media', 'alumni_historiek_delete_media');
}

function alumni_historiek_media_size(int $bytes): string {
    return $bytes >= 1024 * 1024
        ? number_format_i18n($bytes / (1024 * 1024), 2) . ' MB'
        : number_format_i18n($bytes / 1024, 2) . ' KB';
}

function alumni_historiek_render_media_screen(): void {
    if (!current_user_can('manage_options')) {
        wp_die('Je hebt geen rechten om deze pagina te bekijken.');
    }
    $url = admin_url('admin.php?page=alumni-historiek-media');
    $storage = alumni_historiek_storage_info();
    try {
        $files = alumni_historiek_media_inventory($storage);
    } catch (RuntimeException $error) {
        $files = new WP_Error('media_inventory', $error->getMessage());
    }
    echo '<div class="wrap"><h1>Historiek media</h1>';
    echo '<p><a href="' . esc_url(admin_url('admin.php?page=alumni-historiek')) . '">Terug naar instellingen en concertbeheer</a></p>';
    echo '<p>Afbeeldingen, concertposters, videoposters en videos in de actieve concertmap: <code>' . esc_html($storage['concerts_dir']) . '</code>.</p>';
    echo '<p>Ja = zichtbaar op een concertkaart of in de bijbehorende lightbox (inclusief volledige afbeeldingen en videoposters). Alleen bestanden zonder concertkoppeling zijn verweesd en kunnen worden verwijderd. Gekoppelde, niet-getoonde bestanden blijven beschermd.</p>';
    echo '<p>Andere WordPress-media, vaste vormgevingsbestanden en inactieve opslaglocaties vallen buiten deze lijst.</p>';
    if (is_wp_error($files)) {
        echo '<div class="notice notice-error"><p>' . esc_html($files->get_error_message()) . '</p></div></div>';
        return;
    }
    if (isset($_GET['deleted']) && $_GET['deleted'] === '1') {
        echo '<div class="notice notice-success is-dismissible"><p>Mediabestand verwijderd.</p></div>';
    }
    $selected = isset($_GET['file']) && is_string($_GET['file']) ? wp_unslash($_GET['file']) : '';
    if ($selected !== '') {
        if (!isset($files[$selected]) || $files[$selected]['referenced']) {
            echo '<div class="notice notice-error"><p>Dit bestand ontbreekt of is gekoppeld aan een concert. Verwijderen is niet toegestaan.</p></div>';
        } else {
            echo '<div class="notice notice-warning"><h2>Bestand definitief verwijderen?</h2>';
            echo '<p><strong>' . esc_html($selected) . '</strong> is niet gekoppeld aan een concert. Deze actie kan niet ongedaan worden gemaakt. Maak zo nodig eerst een back-up.</p>';
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
            echo '<input type="hidden" name="action" value="alumni_historiek_delete_media">';
            echo '<input type="hidden" name="file" value="' . esc_attr($selected) . '">';
            echo '<input type="hidden" name="storage_mode" value="' . esc_attr($storage['mode']) . '">';
            wp_nonce_field('alumni_historiek_delete_media|' . $storage['mode'] . '|' . $selected);
            echo '<p><button class="button button-primary" type="submit">Definitief verwijderen</button> <a class="button" href="' . esc_url($url) . '">Annuleren</a></p></form></div>';
        }
    }
    $orphans = count(array_filter($files, static function (array $file): bool {
        return !$file['referenced'];
    }));
    echo '<p>' . esc_html(count($files) . ' bestanden; ' . $orphans . ' verweesd.') . '</p>';
    echo '<div role="region" aria-label="Concertmedia" tabindex="0" style="overflow-x:auto;">';
    echo '<table class="widefat striped"><caption class="screen-reader-text">Media in de actieve concertmap</caption>';
    echo '<thead><tr><th scope="col">Bestandsnaam (relatief pad)</th><th scope="col">Extensie</th><th scope="col">Grootte</th><th scope="col">Zichtbaar op concertkaart</th><th scope="col">Actie</th></tr></thead><tbody>';
    foreach ($files as $file) {
        $status = $file['visible'] ? 'Ja' : ($file['referenced'] ? 'Nee - wel gekoppeld' : 'Nee - verweesd');
        $media_url = alumni_historiek_media_url($storage['base_url'] . '/concerts', $file['filename']);
        echo '<tr><th scope="row" style="overflow-wrap:anywhere;"><a href="' . esc_url($media_url) . '" target="_blank" rel="noopener noreferrer" aria-label="' . esc_attr('Bekijk ' . $file['filename'] . ' (opent in een nieuw tabblad)') . '">' . esc_html($file['filename']) . '</a></th>';
        echo '<td>' . esc_html($file['extension']) . '</td><td style="white-space:nowrap;">' . esc_html(alumni_historiek_media_size($file['size'])) . '</td>';
        echo '<td>' . esc_html($status) . '</td><td>';
        if (!$file['referenced']) {
            echo '<a href="' . esc_url(add_query_arg('file', $file['filename'], $url)) . '" aria-label="' . esc_attr('Verwijder ' . $file['filename']) . '">Verwijderen</a>';
        } else {
            echo '&mdash;';
        }
        echo '</td></tr>';
    }
    if (!$files) {
        echo '<tr><td colspan="5">Geen mediabestanden gevonden.</td></tr>';
    }
    echo '</tbody></table></div></div>';
}
