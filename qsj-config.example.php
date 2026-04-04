<?php
// ============================================================
// QsjAuth - per-site configuration
// Copy this to your site root as qsj-config.php and adjust.
// ============================================================

return [
    // URL of your QSJ server (no trailing slash)
    'qsj_base_url' => 'https://qsj.magictintin.fr',

    // How long (seconds) to trust a validated session locally
    // before redirecting to QSJ to silently re-validate.
    // The user won't notice - QSJ will auto-login via remember-me cookie.
    // Shorter = more secure. 3600 = 1 hour is a good default.
    'local_session_ttl' => 3600,

    // Optional: give this site its own session name to avoid conflicts
    // 'session_name' => 'mysite_sess',
];