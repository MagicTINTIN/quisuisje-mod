<?php
// ============================================================
// Qui suis-je module login
// ============================================================
declare(strict_types=1);

class QsjAuth
{
    private string $qsjLogin;
    private string $qsjLogout;
    private string $qsjValidate;
    private string $qsjSilentCheck;
    private int    $localSessionTtl;

    /**
     * @param array{
     *   qsj_base_url:       string,
     *   local_session_ttl?: int,    // seconds, default 3600
     *   session_name?:      string,
     * } $config
     */
    public function __construct(private readonly array $config)
    {
        $base = rtrim($config['qsj_base_url'], '/');
        $this->qsjLogin        = $base . '/login';
        $this->qsjLogout       = $base . '/logout';
        $this->qsjValidate     = $base . '/validate';
        $this->qsjSilentCheck  = $base . '/silent_check';
        $this->localSessionTtl = $config['local_session_ttl'] ?? 3600;

        if (session_status() === PHP_SESSION_NONE) {
            if (isset($config['session_name'])) {
                session_name($config['session_name']);
            }
            session_start();
        }
    }

    // Public API

    /**
     * Enforce authentication. Redirects to Qui suis-je ? if not logged in.
     * Returns the user array on success.
     *
     * Usage: $user = $qsj->requireAuth();
     */
    public function requireAuth(): array
    {
        unset($_SESSION['_qsj_not_logged_in']);
        if ($user = $this->resolveUser()) {
            return $user;
        }
        $this->redirectToQuisuisje();
    }

    /**
     * Check auth without redirecting to the login form. Returns user array or null.
     *
     * @param bool $force  When true, performs a silent round-trip to the QSJ server
     *                     to check whether a global session/remember-me cookie exists,
     *                     even if no local session is present. Useful for pages that are
     *                     public but want to greet a logged-in user.
     *
     *                     Flow when $force = true and no local session:
     *                       1. Browser is redirected to qsj.magictintin.fr/silent_check
     *                       2. QSJ checks its own session / remember-me cookie silently
     *                       3a. If logged in -> redirected back with ?qsj_ticket=...
     *                       3b. If not       -> redirected back with ?qsj_not_logged_in=1
     *                     On the second page load the result is known and no further
     *                     redirect is made.
     *
     *                     ⚠ This causes one extra redirect per cold visit.
     *                       Do not use on every page if most visitors are anonymous.
     */
    public function getUser(bool $force = false): ?array
    {
        return $this->resolveUser($force);
    }

    /**
     * Returns true if a valid session (local or, with $force, global) exists.
     *
     * @param bool $force  See getUser() - same silent-check behaviour.
     */
    public function isAuthenticated(bool $force = false): bool
    {
        return $this->resolveUser($force) !== null;
    }

    /**
     * Log out locally and redirect to Qui suis-je ? global logout.
     *
     * @param string $returnUrl  URL to land on after Qui suis-je ? logout (default: current page)
     */
    public function logout(string $returnUrl = ''): never
    {
        $this->clearLocalSession();
        $returnUrl = $returnUrl ?: $this->currentUrl();
        header('Location: ' . $this->qsjLogout . '?from=' . urlencode($returnUrl));
        exit;
    }

    /**
     * Log out locally only (keeps Qui suis-je ?/global session alive).
     * Useful for "switch account" flows.
     */
    public function logoutLocal(): void
    {
        $this->clearLocalSession();
    }

    /**
     * Returns the login URL (redirect to Qui suis-je ?) without actually redirecting.
     * Handy for building a "Sign in" link in a nav bar.
     */
    public function loginUrl(string $returnUrl = ''): string
    {
        $from = $returnUrl ?: $this->currentUrl();
        return $this->qsjLogin . '?from=' . urlencode($from);
    }

    private function isNonInteractiveBrowser(): bool
    {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // No UA at all - likely a raw bot/tool
        if ($ua === '') return true;

        // Cloudflare header for verified bots (free plan included)
        // verified when CF recognizes a "good" bot (Googlebot, Bingbot, etc.)
        if (($_SERVER['HTTP_CF_IS_BOT'] ?? '') === 'verified') return true;

        // User-Agent pattern matching as fallback (covers social embeds, scrapers, etc.)
        $patterns = [
            // Search engines
            'Googlebot',
            'bingbot',
            'Slurp',
            'DuckDuckBot',
            'Baiduspider',
            'YandexBot',
            'Sogou',
            'Exabot',
            'facebot',
            'ia_archiver',
            // Social / embed fetchers
            'Twitterbot',
            'Discordbot',
            'LinkedInBot',
            'WhatsApp',
            'Slackbot',
            'TelegramBot',
            'FacebookExternalHit',
            'Pinterest',
            // Generic bot signals
            'bot',
            'crawl',
            'spider',
            'scrape',
            'preview',
            'fetch',
            'curl',
            'wget',
            'python-requests',
            'axios',
            'Go-http-client',
        ];

        $pattern = '/' . implode('|', array_map('preg_quote', $patterns)) . '/i';
        return (bool) preg_match($pattern, $ua);
    }

    // Internal

    /**
     * Core resolution:
     *   1. Valid local session               -> return user immediately
     *   2. Incoming qsj_ticket in URL        -> validate, store, clean URL, redirect
     *   3. qsj_not_logged_in flag in URL     -> clean URL, return null (force check done)
     *   4. $force = true, none of the above  -> redirect to silent_check.php (one bounce)
     *   5. Otherwise                         -> return null
     */
    private function resolveUser(bool $force = false): ?array
    {
        // Valid local session - fast path, no network call needed
        if ($this->hasValidLocalSession()) {
            return $_SESSION['_qsj_user'];
        }

        // QSJ ticket (from login.php OR silent_check.php)
        if (isset($_GET['qsj_ticket'])) {
            $user = $this->validateTicket((string)$_GET['qsj_ticket']);
            if ($user !== null) {
                $this->storeLocalSession($user);
                unset($_SESSION['_qsj_not_logged_in']);
                // Strip ticket from URL and redirect (clean URL)
                header('Location: ' . $this->currentUrlWithout('qsj_ticket'));
                exit;
            }
            // Invalid / expired ticket -> fall through as unauthenticated
        }

        // QSJ silent check already ran and confirmed: not logged in
        //    Clean the flag from the URL and return null.
        if (isset($_GET['qsj_not_logged_in'])) {
            $_SESSION['_qsj_not_logged_in'] = true;
            header('Location: ' . $this->currentUrlWithout('qsj_not_logged_in'));
            exit;
        }

        // Force a silent check against QSJ (one redirect round-trip, no login form)
        if ($force && !isset($_SESSION['_qsj_not_logged_in']) &&  !$this->isNonInteractiveBrowser()) {
            $this->redirectToSilentCheck();
        }

        // No session, no force - definitively unauthenticated
        return null;
    }

    private function hasValidLocalSession(): bool
    {
        return isset($_SESSION['_qsj_user'], $_SESSION['_qsj_expires'])
            && is_int($_SESSION['_qsj_expires'])
            && $_SESSION['_qsj_expires'] > time();
    }

    private function storeLocalSession(array $user): void
    {
        $_SESSION['_qsj_user']    = $user;
        $_SESSION['_qsj_expires'] = time() + $this->localSessionTtl;
    }

    private function clearLocalSession(): void
    {
        unset($_SESSION['_qsj_user'], $_SESSION['_qsj_expires']);
    }

    /**
     * Call Qui suis-je ? validate endpoint server-to-server and return user array or null.
     */
    private function validateTicket(string $ticket): ?array
    {
        $url = $this->qsjValidate . '?ticket=' . urlencode($ticket);

        $ctx  = stream_context_create(['http' => [
            'timeout'     => 5,
            'method'      => 'GET',
            'ignore_errors' => true,
        ]]);
        $body = @file_get_contents($url, false, $ctx);

        if ($body === false) return null; // network error

        $data = json_decode($body, true);
        if (!is_array($data) || empty($data['valid'])) return null;

        return $data['user'] ?? null;
    }

    private function redirectToQuisuisje(): never
    {
        header('Location: ' . $this->qsjLogin . '?from=' . urlencode($this->currentUrl()));
        exit;
    }

    private function redirectToSilentCheck(): never
    {
        header('Location: ' . $this->qsjSilentCheck . '?from=' . urlencode($this->currentUrl()));
        exit;
    }

    private function currentUrl(): string
    {
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        return $scheme . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    }

    private function currentUrlWithout(string $param): string
    {
        $url   = $this->currentUrl();
        $clean = preg_replace(
            '/([?&])' . preg_quote($param, '/') . '=[^&]*(&|$)/',
            '$1',
            $url
        );
        // Fix trailing ? or & left behind
        return rtrim(preg_replace('/[?&]$/', '', $clean), '?&');
    }
}
