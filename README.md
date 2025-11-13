# CoD4X Web RCON Tool

A lightweight, single-folder PHP RCON web tool for Call of Duty 4x servers.

- Send RCON commands from a browser
- Saved servers (name/IP/port/RCON) with per‑server logs
- Kick / tempban / permaban players via `clientKick`, `tempBanClient`, and `banClient`
- Simple website‑managed ban list backed by `config/bans.json` and mirrored to `rcon_logs/banlist.log`
- Auth system with JSON‑backed users, login throttling, and admin / mod roles

> **Status:** First public GitHub release (v1.0.0). Tool is designed to be dropped into `/var/www/html/rcon` on a typical Apache + PHP stack.

---

## Features

### RCON Control
- Select a saved server or manually type IP / port / RCON
- Execute any RCON command
- View raw RCON response in the browser

### Player Management
- Kick a player by slot
- Tempban via `tempBanClient <slot> <seconds>`
- Permanent ban via `banClient <slot>`

All actions are logged to `rcon_logs/` (and per‑server subfolders when a saved server is used).

### Logs Tab
- View tail of auth, commands, kicks, tempbans, bans, etc.
- Switch **scope** between:
  - **Global logs** (`rcon_logs/*.log`)
  - **Per‑server logs** (`rcon_logs/servers/<serverId>/*.log`) when a saved server is selected

### Website Ban List
- Bans page lets you:
  - View current website‑managed bans from `config/bans.json`
  - Unban by **GUID** or **Ban ID**
- Bans are also mirrored to `rcon_logs/banlist.log` for auditing.

### Users & Roles
- Users stored in `config/users.json`
- Supports:
  - **Admins**: full control; can see and edit RCON passwords and server list
  - **Moderators**: can use the panel without seeing raw RCON passwords
- Login protection:
  - Throttling after too many failures
  - Logs login success/failure to `rcon_logs/auth.log`

---

## Requirements

- PHP 7.4+ (no external libraries required)
- Apache or Nginx with PHP‑FPM
- CoD4x server(s) reachable from the webserver
- HTTPS strongly recommended (panel is security‑sensitive)

---

## Installation

1. **Copy files**

   ```bash
   sudo mkdir -p /var/www/html/rcon
   sudo cp -r . /var/www/html/rcon
   sudo chown -R www-data:www-data /var/www/html/rcon
   sudo chmod -R 750 /var/www/html/rcon
   ```

2. **Config & logs directories**

   ```bash
   sudo -u www-data mkdir -p /var/www/html/rcon/config /var/www/html/rcon/rcon_logs
   ```

3. **Create real config from examples**

   ```bash
   cd /var/www/html/rcon/config
   sudo -u www-data cp users.json.example users.json
   sudo -u www-data cp servers.json.example servers.json
   sudo -u www-data cp bans.json.example bans.json

   sudo chmod 640 /var/www/html/rcon/config/*.json
   ```

   - Default login (first‑run) is:

     - **Username:** `admin`
     - **Password:** `changeme`

     Change this immediately after logging in.

4. **Apache (example)**

   Make sure your VirtualHost points to `/var/www/html/rcon` and PHP is enabled. Example:

   ```apacheconf
   <VirtualHost *:80>
     ServerName yourpanel.example.com
     DocumentRoot /var/www/html/rcon

     <Directory /var/www/html/rcon>
       AllowOverride All
       Require all granted
     </Directory>
   </VirtualHost>
   ```

   Then:

   ```bash
   sudo a2enmod rewrite
   sudo systemctl reload apache2
   ```

---

## Usage

1. Browse to the panel’s URL (e.g. `http://yourpanel.example.com`).
2. Log in with the admin account.
3. Go to **Users** and update the admin password (and/or create more users).
4. Go to **Servers** and:
   - Add each CoD4x server by name, host/IP, port, and RCON password.
5. Use the **Control** tab to:
   - Select a saved server
   - Send RCON commands
   - Kick / tempban / ban players from the live player list
6. Use the **Logs** tab to monitor auth, commands, kicks, and bans.
7. Use the **Bans** tab to manage website‑stored bans.

---

## Security Notes

- **Always use HTTPS** in production.
- Restrict access:
  - IP‑whitelist the panel if possible (e.g. only your home/office).
  - Or put it behind a VPN.
- Change the default admin password on first login.
- Keep `config/` and `rcon_logs/` owned by the web user (e.g. `www-data`) and not world‑readable.
- Never expose this panel directly to the public internet without additional protections.

---

## Development

This project is intentionally simple:

- No database – all state is JSON (`config/*.json`) and text logs (`rcon_logs/*.log`).
- No frameworks – plain PHP and a single CSS file in `assets/`.

If you want to hack on it:

- Start a PHP built‑in server:

  ```bash
  php -S 127.0.0.1:8080 -t .
  ```

- Point your browser at `http://127.0.0.1:8080/login.php`.

---

## Roadmap / Ideas

- Optional 2FA for admin accounts
- Per‑user permissions (e.g. ban‑only mods)
- JSON export/import for bans
- Dark theme toggle
- Dockerfile for one‑command deployment

---

## License

Released under the **MIT License**. See [`LICENSE`](LICENSE) for details.
