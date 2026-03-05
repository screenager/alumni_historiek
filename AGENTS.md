# Agent Instructions

## Versioned HTML Files

This repository contains versioned HTML files:
- postcards.html
- postcards2.html
- postcards3.html
- etc.

The highest numbered file is the latest version.

tegels.html can be ignored, this was an early idea of the project.

## Rules for Agents

1. Always identify the highest numbered `pageX.html`.
2. Treat that file as the current working version.
3. Never modify older versions, unless explicitly instructed to do so.
4. If creating a new version (only when instructed), follow these steps:
    - Copy the highest version
    - Increment the number
    - Work only on the new highest version


When making a new change or feature, always suggest to also support the mobile view of the page, and support for accessibility.

## Runtime Modes

This project must stay compatible with two runtime modes:

1. **WordPress plugin mode**
   - Public page is served via `/historiek` (theme wrapper bypassed).
   - Admin is opened from WordPress menu (`wp-admin/admin.php?page=alumni-historiek`).
   - Authentication is WordPress authentication/authorization.
   - Storage uses plugin directory when writable, or WordPress uploads fallback.
   - Frontend should hide standalone dev navigation (hamburger/menu links).

2. **Standalone local mode**
   - Public page is available directly via `/index.html` or a specific version like `/postcards6.html`.
   - Admin is available via `/admin/`.
   - Authentication uses local standalone login flow (`private/passwd`).
   - Storage stays in local project files (`concertData.json`, `concerts/`, `private/`).
   - Frontend dev navigation (hamburger/menu links) should remain available.
