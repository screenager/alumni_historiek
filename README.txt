Alumni Historiek
================

This project supports 2 runtime modes.

1) WordPress Plugin Mode
------------------------
- Plugin file: alumni-historiek.php
- Public page URL: /historiek
- Admin page URL: /wp-admin/admin.php?page=alumni-historiek
- Auth: WordPress login + capability checks
- Theme wrapper: bypassed on /historiek (raw page render)
- Storage:
  - Preferred: plugin directory (if writable)
  - Fallback: /wp-content/uploads/alumni-historiek/
- Frontend dev nav (hamburger/menu links): hidden in WordPress mode

2) Standalone Local Mode
------------------------
- Public page URL: /postcards6.html
- Admin page URL: /admin/
- Auth: local login using private/passwd
- Storage: local files in this project directory:
  - concertData.json
  - concerts/
  - private/
- Frontend dev nav (hamburger/menu links): visible

Versioned HTML Rule
-------------------
- postcards.html, postcards2.html, postcards3.html, ... are versioned.
- The highest-numbered postcards file is the current version.
- Current working frontend version: postcards6.html.
- Do not edit older versions unless explicitly requested.

Notes
-----
- In WordPress mode, concertData.json is cache-busted with a version query string.
- If plugin ZIP upload fails due memory/security scanner limits, install by copying
  the plugin folder directly into wp-content/plugins and activate from WP admin.
