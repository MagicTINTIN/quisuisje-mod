# quisuisje-mod - QSJ Authentication Submodule

## Installation (as git submodule)

```bash
# In your site repo root:
git submodule add git@github.com:MagicTINTIN/quisuisje-mod.git qsj
git submodule update --init
```

Copy the example config:
```bash
cp qsj/qsj-config.example.php qsj-config.php
# Edit qsj-config.php with your QSJ server URL
```

---

## Usage

### Protect a page (redirect to QSJ if not logged in)

```php
<?php
require_once __DIR__ . '/qsj/auth.php';

$config = require __DIR__ . '/qsj-config.php';
$qsj    = new QsjAuth($config);

$user = $qsj->requireAuth();
// $user = ['id' => 1, 'username' => 'alice', 'email' => 'alice@example.org']

echo "Hello, " . htmlspecialchars($user['username']);
```

### Optional auth (public page that shows different UI when logged in)

```php
<?php
require_once __DIR__ . '/qsj/auth.php';

$qsj  = new QsjAuth(require __DIR__ . '/qsj-config.php');
$user = $qsj->getUser(); // null if not logged in

if ($user) {
    echo "Logged in as " . $user['username'];
} else {
    echo '<a href="' . $qsj->loginUrl() . '">Sign in</a>';
}
```

### Logout button

```php
// logout.php on your site
require_once __DIR__ . '/qsj/auth.php';
$qsj = new QsjAuth(require __DIR__ . '/qsj-config.php');
$qsj->logout('https://yoursite.com'); // or leave empty for current page
```

---

## How it works

```
Browser                  yoursite.com            qsj.magictintin.fr
  |                           |                        |
  |-- GET /page ------------->|                        |
  |                           | No local session       |
  |<-- 302 /login.php?from=…  |----------------------->|
  |                                                    |
  |-- GET /login.php?from=yoursite.com --------------->|
  |<-- Login page (or auto-login via remember-me) -----|
  |                                                    |
  |-- POST credentials ------------------------------->|
  |<-- 302 yoursite.com/page?qsj_ticket=ST-xxxx -------|
  |                           |                        |
  |-- GET /page?qsj_ticket=…->|                        |
  |                           |-- validate?ticket=… -->|
  |                           |<-- { valid, user } ----|
  |                           | Set local session      |
  |<-- 302 /page (clean URL)  |                        |
  |-- GET /page ------------->|                        |
  |<-- Protected content -----|                        |
```

## Local session TTL

The submodule stores the validated user in PHP `$_SESSION` with a TTL
(`local_session_ttl`, default 3600 s). After expiry, the user is silently
bounced to QSJ - if the remember-me cookie is still valid on `qsj.magictintin.fr`
they are re-authenticated transparently with no login prompt.

**This means:**
- `local_session_ttl` controls how often clients re-check with QSJ.
- The remember-me cookie on QSJ (default 30 days) controls the true "stay logged in" duration.
- Logout calls `qsj.magictintin.fr/logout.php`, which destroys the remember-me cookie/token.
  Local sessions on other sites will expire naturally within their TTL window.
  Set a short TTL (e.g. 300 s) if near-instant cross-site logout is important.

## Requirements

- PHP 8.1+
- `allow_url_fopen = On` in php.ini (for server-to-server ticket validation)
  OR replace `file_get_contents` in `validateTicket()` with a cURL call.