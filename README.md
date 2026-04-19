# Alumni Historiek
Repository: https://github.com/screenager/alumni_historiek

This project supports 2 runtime modes.

1. **WordPress Plugin Mode**
- Plugin file: `alumni-historiek.php`
- Public page URL: `/historiek`
- Admin page URL: `/wp-admin/admin.php?page=alumni-historiek`
- Auth: WordPress login + capability checks
- Theme wrapper: selectable in plugin settings
  - In WordPress thema (header/footer van BeTheme)
  - Volledige standalone pagina (zonder BeTheme)
- Storage:
  - Preferred: plugin directory (if writable)
  - Fallback: `/wp-content/uploads/alumni-historiek/`
- Frontend dev nav (hamburger/menu links): hidden in WordPress mode

2. **Standalone Local Mode**
- Public page URL: `/postcards7.html`
- Admin page URL: `/admin/`
- Auth: local login using `private/passwd`
- Storage: local files in this project directory
  - `concertData.json`
  - `concerts/`
  - `private/`
- Frontend dev nav (hamburger/menu links): visible

## Versioned HTML Rule
- `postcards.html`, `postcards2.html`, `postcards3.html`, ... are versioned.
- The highest-numbered postcards file is the current version.
- Current working frontend version: `postcards7.html`.
- Do not edit older versions unless explicitly requested.

## GitHub Update Flow (WordPress)
- The plugin checks the latest commit on GitHub for updates from:
  - `https://github.com/screenager/alumni_historiek`
- Default tracked branch: `main` (can be overridden with filter `alumni_historiek_github_updater_config`).
- To publish an update:
  1. Commit and push to GitHub.
  2. In WordPress admin, run update checks and update like a normal plugin.
- For private repositories, define `ALUMNI_HISTORIEK_GITHUB_TOKEN` in `wp-config.php`:
  - `define('ALUMNI_HISTORIEK_GITHUB_TOKEN', 'ghp_...');`
- Optional: override repository/branch/token via filter `alumni_historiek_github_updater_config`.

### Update not showing? GitHub API cache
The GitHub API response is cached for 1 hour (3600 seconds), so a freshly pushed version
may not appear immediately on the WordPress Plugins page.
**Fix:** Go to `wp-admin/admin.php?page=alumni-historiek` and click **"Check for updates now"** —
that forces a cache refresh and the new version should appear on the Plugins page right away.

### Renaming the plugin directory
The plugin directory is currently `alumni_historiek_postcards7` (installed from a ZIP with that name).
To rename it (e.g. to `alumni-historiek`) without losing settings:
1. **Deactivate** the plugin from the WordPress Plugins page.
2. **Rename** the folder on disk:
   ```bash
   mv wp-content/plugins/alumni_historiek_postcards7 wp-content/plugins/alumni-historiek
   ```
3. **Re-activate** the plugin from the Plugins page — WordPress will register the new path.
4. WordPress stores the active plugin path (`old-dir/plugin-file.php`) in `wp_options`.
   Deactivating + reactivating updates it automatically.
5. Plugin-specific options (stored by option name, not by directory) are unaffected.
> Note: any hardcoded references to the old directory path (e.g. in `wp-config.php` or custom code) must be updated manually.

## Notes
- In WordPress mode, `concertData.json` is cache-busted with a version query string.
- If plugin ZIP upload fails due memory/security scanner limits, install by copying
  the plugin folder directly into `wp-content/plugins` and activate from WP admin.
