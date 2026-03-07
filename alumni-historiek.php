<?php
/**
 * Plugin Name: Alumni Historiek
 * Description: Serves the historiek page at /historiek and provides a WordPress-admin integration for managing concert data.
 * Version: 1.0.0
 * Author: Alumni Arenbergorkest
 * Update URI: https://github.com/screenager/alumni_historiek
 */

if (!defined('ABSPATH')) {
    exit;
}

define('ALUMNI_HISTORIEK_PLUGIN_FILE', __FILE__);
define('ALUMNI_HISTORIEK_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('ALUMNI_HISTORIEK_PLUGIN_URL', plugin_dir_url(__FILE__));
define('ALUMNI_HISTORIEK_PLUGIN_BASENAME', plugin_basename(__FILE__));
define('ALUMNI_HISTORIEK_GITHUB_REPO_DEFAULT', 'screenager/alumni_historiek');

function alumni_historiek_github_updater_config(): array {
    $config = [
        'repository' => ALUMNI_HISTORIEK_GITHUB_REPO_DEFAULT,
        'token' => defined('ALUMNI_HISTORIEK_GITHUB_TOKEN') ? (string) ALUMNI_HISTORIEK_GITHUB_TOKEN : '',
        'cache_ttl' => 3600,
    ];

    $config = apply_filters('alumni_historiek_github_updater_config', $config);
    $config['repository'] = is_string($config['repository'] ?? '') ? trim((string) $config['repository']) : '';
    $config['token'] = is_string($config['token'] ?? '') ? trim((string) $config['token']) : '';
    $config['cache_ttl'] = max(300, (int) ($config['cache_ttl'] ?? 3600));

    return $config;
}

function alumni_historiek_get_repo_parts(string $repository): ?array {
    $parts = explode('/', trim($repository, " \t\n\r\0\x0B/"));
    if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
        return null;
    }

    return [$parts[0], $parts[1]];
}

function alumni_historiek_get_plugin_data_cached(): array {
    static $plugin_data = null;
    if (is_array($plugin_data)) {
        return $plugin_data;
    }

    if (!function_exists('get_plugin_data')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }

    $plugin_data = get_plugin_data(ALUMNI_HISTORIEK_PLUGIN_FILE, false, false);
    return is_array($plugin_data) ? $plugin_data : [];
}

function alumni_historiek_github_request_headers(string $token = ''): array {
    $headers = [
        'Accept' => 'application/vnd.github+json',
        'User-Agent' => 'WordPress/' . get_bloginfo('version') . '; ' . home_url('/'),
    ];

    if ($token !== '') {
        $headers['Authorization'] = 'Bearer ' . $token;
    }

    return $headers;
}

function alumni_historiek_get_github_release_data(bool $force_refresh = false): ?array {
    $config = alumni_historiek_github_updater_config();
    if ($config['repository'] === '') {
        return null;
    }
    $repo_parts = alumni_historiek_get_repo_parts($config['repository']);
    if (!is_array($repo_parts)) {
        return null;
    }
    [$owner, $repo] = $repo_parts;

    $cache_key = 'alumni_historiek_github_release_' . md5($config['repository']);
    if (!$force_refresh) {
        $cached = get_site_transient($cache_key);
        if (is_array($cached)) {
            return $cached;
        }
    }

    $response = wp_remote_get(
        'https://api.github.com/repos/' . rawurlencode($owner) . '/' . rawurlencode($repo) . '/releases/latest',
        [
            'headers' => alumni_historiek_github_request_headers($config['token']),
            'timeout' => 15,
        ]
    );

    if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
        return null;
    }

    $body = json_decode((string) wp_remote_retrieve_body($response), true);
    if (!is_array($body)) {
        return null;
    }

    $tag_name = isset($body['tag_name']) ? trim((string) $body['tag_name']) : '';
    $zipball_url = isset($body['zipball_url']) ? trim((string) $body['zipball_url']) : '';
    if ($tag_name === '' || $zipball_url === '') {
        return null;
    }

    $data = [
        'version' => ltrim($tag_name, "vV \t\n\r\0\x0B"),
        'tag' => $tag_name,
        'zipball_url' => $zipball_url,
        'html_url' => isset($body['html_url']) ? (string) $body['html_url'] : '',
        'published_at' => isset($body['published_at']) ? (string) $body['published_at'] : '',
        'body' => isset($body['body']) ? (string) $body['body'] : '',
    ];

    set_site_transient($cache_key, $data, $config['cache_ttl']);
    return $data;
}

function alumni_historiek_filter_update_plugins($transient) {
    if (!is_object($transient)) {
        $transient = new stdClass();
    }

    if (!isset($transient->checked) || !is_array($transient->checked)) {
        return $transient;
    }

    $current_version = isset($transient->checked[ALUMNI_HISTORIEK_PLUGIN_BASENAME])
        ? (string) $transient->checked[ALUMNI_HISTORIEK_PLUGIN_BASENAME]
        : '';
    if ($current_version === '') {
        return $transient;
    }

    $release = alumni_historiek_get_github_release_data();
    if (!is_array($release) || empty($release['version'])) {
        return $transient;
    }

    if (version_compare((string) $release['version'], $current_version, '<=')) {
        return $transient;
    }

    $plugin_data = alumni_historiek_get_plugin_data_cached();

    $transient->response[ALUMNI_HISTORIEK_PLUGIN_BASENAME] = (object) [
        'slug' => dirname(ALUMNI_HISTORIEK_PLUGIN_BASENAME),
        'plugin' => ALUMNI_HISTORIEK_PLUGIN_BASENAME,
        'new_version' => (string) $release['version'],
        'url' => (string) ($release['html_url'] ?? ''),
        'package' => (string) $release['zipball_url'],
        'icons' => [],
        'banners' => [],
        'banners_rtl' => [],
        'tested' => isset($plugin_data['Tested up to']) ? (string) $plugin_data['Tested up to'] : '',
        'requires_php' => isset($plugin_data['RequiresPHP']) ? (string) $plugin_data['RequiresPHP'] : '',
    ];

    return $transient;
}
add_filter('pre_set_site_transient_update_plugins', 'alumni_historiek_filter_update_plugins');

function alumni_historiek_plugins_api($result, string $action, $args) {
    if ($action !== 'plugin_information' || !is_object($args) || !isset($args->slug)) {
        return $result;
    }

    if ((string) $args->slug !== dirname(ALUMNI_HISTORIEK_PLUGIN_BASENAME)) {
        return $result;
    }

    $release = alumni_historiek_get_github_release_data();
    if (!is_array($release)) {
        return $result;
    }

    $plugin_data = alumni_historiek_get_plugin_data_cached();

    return (object) [
        'name' => (string) ($plugin_data['Name'] ?? 'Alumni Historiek'),
        'slug' => dirname(ALUMNI_HISTORIEK_PLUGIN_BASENAME),
        'version' => (string) $release['version'],
        'author' => (string) ($plugin_data['AuthorName'] ?? ''),
        'homepage' => (string) ($release['html_url'] ?? ''),
        'short_description' => (string) ($plugin_data['Description'] ?? ''),
        'sections' => [
            'description' => (string) ($plugin_data['Description'] ?? ''),
            'changelog' => nl2br(esc_html((string) ($release['body'] ?? ''))),
        ],
        'download_link' => (string) $release['zipball_url'],
    ];
}
add_filter('plugins_api', 'alumni_historiek_plugins_api', 10, 3);

function alumni_historiek_http_request_args(array $args, string $url): array {
    $config = alumni_historiek_github_updater_config();
    if ($config['token'] === '') {
        return $args;
    }
    $repo_parts = alumni_historiek_get_repo_parts($config['repository']);
    if (!is_array($repo_parts)) {
        return $args;
    }
    [$owner, $repo] = $repo_parts;

    $zipball_prefix = 'https://api.github.com/repos/' . rawurlencode($owner) . '/' . rawurlencode($repo) . '/zipball/';
    if (strpos($url, $zipball_prefix) !== 0) {
        return $args;
    }

    $args['headers'] = isset($args['headers']) && is_array($args['headers']) ? $args['headers'] : [];
    $args['headers']['Authorization'] = 'Bearer ' . $config['token'];
    $args['headers']['User-Agent'] = $args['headers']['User-Agent'] ?? ('WordPress/' . get_bloginfo('version') . '; ' . home_url('/'));

    return $args;
}
add_filter('http_request_args', 'alumni_historiek_http_request_args', 10, 2);

function alumni_historiek_upgrader_source_selection(string $source, string $remote_source, $upgrader): string {
    if (!is_object($upgrader) || !isset($upgrader->skin) || !is_object($upgrader->skin)) {
        return $source;
    }

    $plugin = $upgrader->skin->plugin ?? '';
    if ($plugin !== ALUMNI_HISTORIEK_PLUGIN_BASENAME) {
        return $source;
    }

    $desired = trailingslashit($remote_source) . dirname(ALUMNI_HISTORIEK_PLUGIN_BASENAME);
    if (untrailingslashit($source) === untrailingslashit($desired)) {
        return $source;
    }

    global $wp_filesystem;
    if (!$wp_filesystem || !$wp_filesystem->move($source, $desired, true)) {
        return $source;
    }

    return $desired;
}
add_filter('upgrader_source_selection', 'alumni_historiek_upgrader_source_selection', 10, 3);

function alumni_historiek_upgrader_process_complete($upgrader, array $options): void {
    if (($options['action'] ?? '') !== 'update' || ($options['type'] ?? '') !== 'plugin') {
        return;
    }

    $plugins = $options['plugins'] ?? [];
    if (!is_array($plugins) || !in_array(ALUMNI_HISTORIEK_PLUGIN_BASENAME, $plugins, true)) {
        return;
    }

    $config = alumni_historiek_github_updater_config();
    $cache_key = 'alumni_historiek_github_release_' . md5($config['repository']);
    delete_site_transient($cache_key);
}
add_action('upgrader_process_complete', 'alumni_historiek_upgrader_process_complete', 10, 2);

function alumni_historiek_get_update_diagnostics(): array {
    $plugin_data = alumni_historiek_get_plugin_data_cached();
    $config = alumni_historiek_github_updater_config();
    $release = alumni_historiek_get_github_release_data();
    $update_plugins = get_site_transient('update_plugins');
    $response_item = null;

    if (is_object($update_plugins) && isset($update_plugins->response) && is_array($update_plugins->response)) {
        $response_item = $update_plugins->response[ALUMNI_HISTORIEK_PLUGIN_BASENAME] ?? null;
    }

    $auto_update_plugins = get_site_option('auto_update_plugins', []);
    $is_auto_update_enabled_for_plugin = is_array($auto_update_plugins)
        && in_array(ALUMNI_HISTORIEK_PLUGIN_BASENAME, $auto_update_plugins, true);

    $is_global_updates_blocked = defined('DISALLOW_FILE_MODS') && DISALLOW_FILE_MODS;
    $is_global_auto_updates_disabled = defined('AUTOMATIC_UPDATER_DISABLED') && AUTOMATIC_UPDATER_DISABLED;

    return [
        'plugin_basename' => ALUMNI_HISTORIEK_PLUGIN_BASENAME,
        'plugin_version' => (string) ($plugin_data['Version'] ?? ''),
        'update_uri' => (string) ($plugin_data['UpdateURI'] ?? ''),
        'github_repository' => (string) ($config['repository'] ?? ''),
        'github_token_configured' => (string) ($config['token'] ?? '') !== '',
        'latest_release_version' => is_array($release) ? (string) ($release['version'] ?? '') : '',
        'latest_release_tag' => is_array($release) ? (string) ($release['tag'] ?? '') : '',
        'latest_release_url' => is_array($release) ? (string) ($release['html_url'] ?? '') : '',
        'latest_release_published_at' => is_array($release) ? (string) ($release['published_at'] ?? '') : '',
        'wp_detected_update_version' => is_object($response_item) ? (string) ($response_item->new_version ?? '') : '',
        'wp_detected_update_package' => is_object($response_item) ? (string) ($response_item->package ?? '') : '',
        'wp_last_checked' => is_object($update_plugins) ? (int) ($update_plugins->last_checked ?? 0) : 0,
        'global_updates_blocked' => $is_global_updates_blocked,
        'global_auto_updates_disabled' => $is_global_auto_updates_disabled,
        'plugin_auto_update_enabled' => $is_auto_update_enabled_for_plugin,
    ];
}

function alumni_historiek_render_diagnostics_table(): void {
    $d = alumni_historiek_get_update_diagnostics();
    $last_checked = $d['wp_last_checked'] > 0
        ? wp_date('Y-m-d H:i:s', $d['wp_last_checked'])
        : 'Unknown';
    $release_url = $d['latest_release_url'] !== ''
        ? '<a href="' . esc_url($d['latest_release_url']) . '" target="_blank" rel="noopener noreferrer">Open release</a>'
        : 'Not available';
    $update_package = $d['wp_detected_update_package'] !== '' ? 'Available' : 'Not detected';
    $update_version = $d['wp_detected_update_version'] !== '' ? $d['wp_detected_update_version'] : 'Not detected';
    $release_version = $d['latest_release_version'] !== '' ? $d['latest_release_version'] : 'Not detected';
    $release_tag = $d['latest_release_tag'] !== '' ? $d['latest_release_tag'] : 'Not detected';
    $published_at = $d['latest_release_published_at'] !== '' ? $d['latest_release_published_at'] : 'Not detected';
    $token_status = $d['github_token_configured'] ? 'Yes' : 'No';
    $global_blocked = $d['global_updates_blocked'] ? 'Yes (DISALLOW_FILE_MODS)' : 'No';
    $global_auto_disabled = $d['global_auto_updates_disabled'] ? 'Yes (AUTOMATIC_UPDATER_DISABLED)' : 'No';
    $plugin_auto_enabled = $d['plugin_auto_update_enabled'] ? 'Yes' : 'No';

    echo '<div class="notice notice-info" style="padding:12px 16px;margin-top:16px;">';
    echo '<h2 style="margin-top:0;">Update diagnostics</h2>';
    echo '<table class="widefat striped" style="max-width:980px;">';
    echo '<tbody>';
    echo '<tr><td style="width:38%;"><strong>Plugin basename</strong></td><td>' . esc_html($d['plugin_basename']) . '</td></tr>';
    echo '<tr><td><strong>Installed version</strong></td><td>' . esc_html($d['plugin_version']) . '</td></tr>';
    echo '<tr><td><strong>Update URI</strong></td><td>' . esc_html($d['update_uri']) . '</td></tr>';
    echo '<tr><td><strong>GitHub repository</strong></td><td>' . esc_html($d['github_repository']) . '</td></tr>';
    echo '<tr><td><strong>GitHub token configured</strong></td><td>' . esc_html($token_status) . '</td></tr>';
    echo '<tr><td><strong>Latest release version (GitHub)</strong></td><td>' . esc_html($release_version) . '</td></tr>';
    echo '<tr><td><strong>Latest release tag (GitHub)</strong></td><td>' . esc_html($release_tag) . '</td></tr>';
    echo '<tr><td><strong>Latest release published (GitHub)</strong></td><td>' . esc_html($published_at) . '</td></tr>';
    echo '<tr><td><strong>Latest release link</strong></td><td>' . $release_url . '</td></tr>';
    echo '<tr><td><strong>WordPress detected update version</strong></td><td>' . esc_html($update_version) . '</td></tr>';
    echo '<tr><td><strong>WordPress detected update package</strong></td><td>' . esc_html($update_package) . '</td></tr>';
    echo '<tr><td><strong>WordPress last update-check</strong></td><td>' . esc_html($last_checked) . '</td></tr>';
    echo '<tr><td><strong>Global updates blocked</strong></td><td>' . esc_html($global_blocked) . '</td></tr>';
    echo '<tr><td><strong>Global auto-updates disabled</strong></td><td>' . esc_html($global_auto_disabled) . '</td></tr>';
    echo '<tr><td><strong>Auto-update enabled for this plugin</strong></td><td>' . esc_html($plugin_auto_enabled) . '</td></tr>';
    echo '</tbody>';
    echo '</table>';
    echo '<p style="margin-bottom:0;">Tip: run "Check for updates" in WordPress Updates screen, then reload this page.</p>';
    echo '</div>';
}

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

function alumni_historiek_should_exclude_from_zip(string $relative_path): bool {
    $relative_path = str_replace('\\', '/', ltrim($relative_path, '/'));
    $base = basename($relative_path);

    if ($relative_path === '.git' || str_starts_with($relative_path, '.git/')) {
        return true;
    }
    if ($relative_path === '.idea' || str_starts_with($relative_path, '.idea/')) {
        return true;
    }
    if ($relative_path === '__MACOSX' || str_starts_with($relative_path, '__MACOSX/')) {
        return true;
    }
    if ($base === '.DS_Store') {
        return true;
    }
    if ($relative_path === 'concertData.json' || $relative_path === 'concerts' || str_starts_with($relative_path, 'concerts/')) {
        return true;
    }

    return false;
}

function alumni_historiek_zip_add_directory(ZipArchive $zip, string $source_dir, string $zip_prefix): void {
    if (!is_dir($source_dir)) {
        return;
    }

    $zip_prefix = trim(str_replace('\\', '/', $zip_prefix), '/');
    if ($zip_prefix !== '') {
        $zip->addEmptyDir($zip_prefix);
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($source_dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );

    foreach ($iterator as $file_info) {
        $absolute_path = $file_info->getPathname();
        $relative = substr($absolute_path, strlen($source_dir) + 1);
        if ($relative === false || $relative === '') {
            continue;
        }

        $relative = str_replace('\\', '/', $relative);
        $zip_path = $zip_prefix !== '' ? $zip_prefix . '/' . $relative : $relative;

        if ($file_info->isDir()) {
            $zip->addEmptyDir($zip_path);
            continue;
        }

        if ($file_info->isFile()) {
            $zip->addFile($absolute_path, $zip_path);
        }
    }
}

function alumni_historiek_download_plugin_zip(): void {
    if (!current_user_can('manage_options')) {
        wp_die('Je hebt geen rechten om deze download uit te voeren.');
    }

    check_admin_referer('alumni_historiek_download_plugin_zip');

    if (!class_exists('ZipArchive')) {
        wp_die('ZipArchive extensie is niet beschikbaar op deze server.');
    }

    $storage = alumni_historiek_storage_info();
    $plugin_root = untrailingslashit(ALUMNI_HISTORIEK_PLUGIN_DIR);
    $tmp_file = wp_tempnam('alumni-historiek-plugin.zip');
    if ($tmp_file === false) {
        wp_die('Kan tijdelijk ZIP-bestand niet aanmaken.');
    }

    $zip_path = $tmp_file . '.zip';
    @unlink($tmp_file);

    $zip = new ZipArchive();
    if ($zip->open($zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        wp_die('Kan ZIP-archief niet aanmaken.');
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($plugin_root, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    $zip_root = 'alumni-historiek';
    $zip->addEmptyDir($zip_root);

    foreach ($iterator as $file_info) {
        $absolute_path = $file_info->getPathname();
        $relative_path = substr($absolute_path, strlen($plugin_root) + 1);
        if ($relative_path === false || $relative_path === '') {
            continue;
        }

        $relative_path = str_replace('\\', '/', $relative_path);
        if (alumni_historiek_should_exclude_from_zip($relative_path)) {
            continue;
        }

        $zip_relative_path = $zip_root . '/' . $relative_path;

        if ($file_info->isDir()) {
            $zip->addEmptyDir($zip_relative_path);
            continue;
        }

        if ($file_info->isFile()) {
            $zip->addFile($absolute_path, $zip_relative_path);
        }
    }

    if (is_file($storage['data_file'])) {
        $zip->addFile($storage['data_file'], $zip_root . '/concertData.json');
    }
    alumni_historiek_zip_add_directory($zip, $storage['concerts_dir'], $zip_root . '/concerts');

    $zip->close();

    if (!is_file($zip_path)) {
        wp_die('ZIP-bestand werd niet gegenereerd.');
    }

    $filename = 'alumni-historiek-plugin-' . gmdate('Ymd-His') . '.zip';
    nocache_headers();
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . (string) filesize($zip_path));
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    readfile($zip_path);
    @unlink($zip_path);
    exit;
}
add_action('admin_post_alumni_historiek_download_plugin_zip', 'alumni_historiek_download_plugin_zip');

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
    $download_url = wp_nonce_url(
        admin_url('admin-post.php?action=alumni_historiek_download_plugin_zip'),
        'alumni_historiek_download_plugin_zip'
    );

    echo '<div class="wrap">';
    echo '<h1>Historiek beheer</h1>';
    echo '<p>De editor draait hieronder met WordPress-authenticatie.</p>';
    echo '<p><a class="button button-secondary" href="' . esc_url($download_url) . '" aria-label="Download plugin ZIP met huidige WordPress data">Download backup of the plugin (met huidige data)</a></p>';
    alumni_historiek_render_diagnostics_table();
    echo '<iframe src="' . $iframe_src . '" style="width:100%;min-height:85vh;border:1px solid #ccd0d4;border-radius:6px;background:#fff"></iframe>';
    echo '</div>';
}

add_action('plugins_loaded', static function () {
    if (get_option('alumni_historiek_storage_mode') === false) {
        alumni_historiek_initialize_storage();
    }
});
