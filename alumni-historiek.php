<?php
/**
 * Plugin Name: Alumni Historiek
 * Description: Serves the historiek page at /historiek and provides a WordPress-admin integration for managing concert data.
 * Version: 1.0.0
 * Author: Alumni Arenbergorkest
 */

if (!defined('ABSPATH')) {
    exit;
}

define('ALUMNI_HISTORIEK_PLUGIN_FILE', __FILE__);
define('ALUMNI_HISTORIEK_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('ALUMNI_HISTORIEK_PLUGIN_URL', plugin_dir_url(__FILE__));

function alumni_historiek_storage_info(): array {
    $mode = get_option('alumni_historiek_storage_mode', 'plugin');

    if ($mode === 'uploads') {
        $uploads = wp_upload_dir();
        $base_dir = trailingslashit($uploads['basedir']) . 'alumni-historiek';
        $base_url = trailingslashit($uploads['baseurl']) . 'alumni-historiek';
        return [
            'mode' => 'uploads',
            'base_dir' => $base_dir,
            'base_url' => $base_url,
            'data_file' => $base_dir . '/concertData.json',
            'concerts_dir' => $base_dir . '/concerts',
            'private_dir' => $base_dir . '/private',
        ];
    }

    return [
        'mode' => 'plugin',
        'base_dir' => untrailingslashit(ALUMNI_HISTORIEK_PLUGIN_DIR),
        'base_url' => untrailingslashit(ALUMNI_HISTORIEK_PLUGIN_URL),
        'data_file' => ALUMNI_HISTORIEK_PLUGIN_DIR . 'concertData.json',
        'concerts_dir' => ALUMNI_HISTORIEK_PLUGIN_DIR . 'concerts',
        'private_dir' => ALUMNI_HISTORIEK_PLUGIN_DIR . 'private',
    ];
}

function alumni_historiek_recursive_copy(string $source, string $destination): void {
    if (is_file($source)) {
        $dest_dir = dirname($destination);
        if (!is_dir($dest_dir)) {
            wp_mkdir_p($dest_dir);
        }
        copy($source, $destination);
        return;
    }

    if (!is_dir($source)) {
        return;
    }

    wp_mkdir_p($destination);

    $items = scandir($source);
    if (!is_array($items)) {
        return;
    }

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $src = $source . '/' . $item;
        $dst = $destination . '/' . $item;

        if (is_dir($src)) {
            alumni_historiek_recursive_copy($src, $dst);
        } else {
            $dst_dir = dirname($dst);
            if (!is_dir($dst_dir)) {
                wp_mkdir_p($dst_dir);
            }
            copy($src, $dst);
        }
    }
}

function alumni_historiek_initialize_storage(): void {
    $plugin_root = untrailingslashit(ALUMNI_HISTORIEK_PLUGIN_DIR);
    $plugin_writable = is_writable($plugin_root);
    $mode = $plugin_writable ? 'plugin' : 'uploads';

    update_option('alumni_historiek_storage_mode', $mode);

    $storage = alumni_historiek_storage_info();

    if (!is_dir($storage['base_dir'])) {
        wp_mkdir_p($storage['base_dir']);
    }
    if (!is_dir($storage['concerts_dir'])) {
        wp_mkdir_p($storage['concerts_dir']);
    }
    if (!is_dir($storage['private_dir'])) {
        wp_mkdir_p($storage['private_dir']);
    }

    if (!file_exists($storage['data_file'])) {
        if ($mode === 'uploads' && file_exists(ALUMNI_HISTORIEK_PLUGIN_DIR . 'concertData.json')) {
            copy(ALUMNI_HISTORIEK_PLUGIN_DIR . 'concertData.json', $storage['data_file']);
        } else {
            $default = [
                'header' => ['h1' => '', 'swipe_hint' => '', 'flip_hint' => ''],
                'concerts' => [],
            ];
            file_put_contents($storage['data_file'], wp_json_encode($default, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n");
        }
    }

    if ($mode === 'uploads') {
        $target_concerts = $storage['concerts_dir'];
        $concert_entries = @scandir($target_concerts);
        if (!is_dir($target_concerts) || !is_array($concert_entries) || count($concert_entries) <= 2) {
            alumni_historiek_recursive_copy(ALUMNI_HISTORIEK_PLUGIN_DIR . 'concerts', $target_concerts);
        }

        $target_private = $storage['private_dir'];
        $private_entries = @scandir($target_private);
        if (!is_dir($target_private) || !is_array($private_entries) || count($private_entries) <= 2) {
            alumni_historiek_recursive_copy(ALUMNI_HISTORIEK_PLUGIN_DIR . 'private', $target_private);
        }
    }
}

function alumni_historiek_plugin_activate(): void {
    alumni_historiek_initialize_storage();
    alumni_historiek_register_rewrite();
    flush_rewrite_rules();
}
register_activation_hook(__FILE__, 'alumni_historiek_plugin_activate');

function alumni_historiek_plugin_deactivate(): void {
    flush_rewrite_rules();
}
register_deactivation_hook(__FILE__, 'alumni_historiek_plugin_deactivate');

function alumni_historiek_register_rewrite(): void {
    add_rewrite_rule('^historiek/?$', 'index.php?alumni_historiek=1', 'top');
}
add_action('init', 'alumni_historiek_register_rewrite');

function alumni_historiek_register_query_var(array $vars): array {
    $vars[] = 'alumni_historiek';
    return $vars;
}
add_filter('query_vars', 'alumni_historiek_register_query_var');

function alumni_historiek_get_latest_postcards_html_path(): ?string {
    $candidates = glob(ALUMNI_HISTORIEK_PLUGIN_DIR . 'postcards*.html');
    if (!is_array($candidates) || $candidates === []) {
        return null;
    }

    $latest_path = null;
    $latest_version = -1;

    foreach ($candidates as $path) {
        $filename = basename($path);
        if (preg_match('/^postcards(\d+)\.html$/', $filename, $matches) !== 1) {
            continue;
        }

        $version = (int) $matches[1];
        if ($version > $latest_version) {
            $latest_version = $version;
            $latest_path = $path;
        }
    }

    if ($latest_path !== null) {
        return $latest_path;
    }

    $fallback = ALUMNI_HISTORIEK_PLUGIN_DIR . 'postcards.html';
    return file_exists($fallback) ? $fallback : null;
}

function alumni_historiek_render_page(): void {
    if ((int) get_query_var('alumni_historiek') !== 1) {
        return;
    }

    $html_path = alumni_historiek_get_latest_postcards_html_path();
    if ($html_path === null || !file_exists($html_path)) {
        status_header(404);
        echo 'No postcards HTML file found.';
        exit;
    }

    $storage = alumni_historiek_storage_info();
    $html = file_get_contents($html_path);
    if ($html === false) {
        status_header(500);
        echo 'Unable to load historiek page.';
        exit;
    }

    $base_href = esc_url(ALUMNI_HISTORIEK_PLUGIN_URL);
    $admin_link = esc_url(admin_url('admin.php?page=alumni-historiek'));
    $data_version = @filemtime($storage['data_file']) ?: time();
    $data_url = esc_url(add_query_arg('v', (string) $data_version, $storage['base_url'] . '/concertData.json'));
    $concerts_base = esc_url($storage['base_url'] . '/concerts/');

    $inject = "<base href=\"{$base_href}\">\n";
    $inject .= "<script>window.HISTORIEK_DATA_URL = " . wp_json_encode($data_url) . "; window.HISTORIEK_ASSETS_BASE_URL = " . wp_json_encode($concerts_base) . "; window.HISTORIEK_IS_WORDPRESS = true;</script>\n";

    $html = preg_replace('/<head>/', "<head>\n{$inject}", $html, 1);
    $html = str_replace('href="admin/index.html"', 'href="' . esc_attr($admin_link) . '"', $html);

    nocache_headers();
    header('Content-Type: text/html; charset=utf-8');
    echo $html;
    exit;
}
add_action('template_redirect', 'alumni_historiek_render_page', 0);

function alumni_historiek_add_admin_menu(): void {
    add_menu_page(
        'Historiek beheer',
        'Historiek',
        'manage_options',
        'alumni-historiek',
        'alumni_historiek_render_admin_screen',
        'dashicons-images-alt2',
        28
    );
}
add_action('admin_menu', 'alumni_historiek_add_admin_menu');

function alumni_historiek_render_admin_screen(): void {
    if (!current_user_can('manage_options')) {
        wp_die('Je hebt geen rechten om deze pagina te bekijken.');
    }

    $iframe_src = esc_url(ALUMNI_HISTORIEK_PLUGIN_URL . 'admin/index.html');
    echo '<div class="wrap">';
    echo '<h1>Historiek beheer</h1>';
    echo '<p>De editor draait hieronder met WordPress-authenticatie.</p>';
    echo '<iframe src="' . $iframe_src . '" style="width:100%;min-height:85vh;border:1px solid #ccd0d4;border-radius:6px;background:#fff"></iframe>';
    echo '</div>';
}

add_action('plugins_loaded', static function () {
    if (get_option('alumni_historiek_storage_mode') === false) {
        alumni_historiek_initialize_storage();
    }
});
