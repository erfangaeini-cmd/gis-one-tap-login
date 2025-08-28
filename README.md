# gis-one-tap-login
# GIS One Tap Auto Login (WordPress Plugin)

Google One Tap Login with auto-select for WordPress. Includes dashboard widget for quick settings and inline help.

## Features
- Google Identity Services (One Tap)
- Auto-select, ITP support, prompt-on-load toggles
- Server-side ID token validation
- Admin Dashboard widget (settings + help)

## Installation
1. Upload the plugin folder to `wp-content/plugins/`.
2. Activate via **Plugins** in WordPress.
3. Go to **Dashboard → Home** (ویجت GIS) یا **Settings → GIS One Tap Login** و Client ID را وارد کنید.

## Configure Google Web Client ID
- Google Cloud Console → OAuth consent screen (External) → Authorized domains
- Credentials → Create Credentials → **OAuth client ID** (Web application)
- Authorized JavaScript origins:
  - `https://your-domain.com`
  - `https://www.your-domain.com`

## Changelog
- v1.3.3 – Initial GitHub release.
![License](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)
![Release](https://img.shields.io/github/v/release/erfangaeini-cmd/gis-one-tap-login)
