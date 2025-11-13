# Changelog

## v1.0.0 – First Public GitHub Release

- Cleaned up bans page UI and website‑managed ban storage (`config/bans.json`).
- Ensured tempban / ban buttons use `tempBanClient` and `banClient` for CoD4x.
- Added per‑server logs under `rcon_logs/servers/<serverId>/...` when using saved servers.
- Centralized user auth in `config/auth.php` with JSON‑backed users and roles.
- Added `.gitignore` to keep local config and runtime logs out of version control.
- Added example config files in `config/*.json.example` for safer deployment.
- Added MIT license.
