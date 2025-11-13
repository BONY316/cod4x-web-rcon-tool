Hotfix: Login reads users.json; settings save hardened
=======================================================

**What’s fixed**
- `login.php` now authenticates against **config/users.json** via `auth_load_users()`
  (fallbacks to inline `$USERS` only if JSON doesn’t exist).
- `settings.php` unchanged functionally, but messages improved and save path verified.

**Deploy**
```bash
sudo cp /var/www/html/rcon/login.php /var/www/html/rcon/login.php.bak-$(date +%s) || true
sudo cp /var/www/html/rcon/settings.php /var/www/html/rcon/settings.php.bak-$(date +%s) || true

sudo cp hotfix/login.php /var/www/html/rcon/login.php
sudo cp hotfix/settings.php /var/www/html/rcon/settings.php
sudo chown www-data:www-data /var/www/html/rcon/login.php /var/www/html/rcon/settings.php
sudo chmod 640 /var/www/html/rcon/login.php /var/www/html/rcon/settings.php
```

**Permissions check (only if needed)**
```bash
sudo chown -R www-data:www-data /var/www/html/rcon/config
sudo chmod -R 750 /var/www/html/rcon/config
sudo touch /var/www/html/rcon/config/users.json
sudo chown www-data:www-data /var/www/html/rcon/config/users.json
sudo chmod 640 /var/www/html/rcon/config/users.json
```

Generated 2025-11-12.
