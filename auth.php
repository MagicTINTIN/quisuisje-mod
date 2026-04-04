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
        if ($user = $this->resolveUser()) {
            return $user;
        }
        $this->redirectToQuisuisje();
    }

    /**
     * Check auth without redirecting. Returns user array or null.
     */
    public function getUser(): ?array
    {
        return $this->resolveUser();
    }

    /**
     * Returns true if a valid local session (or a fresh ticket) exists.
     */
    public function isAuthenticated(): bool
    {
        return $this->resolveUser() !== null;
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

    // Internal

    /**
     * Core resolution: check local session -> validate ticket -> return user or null.
     * Side-effect: consumes ticket from URL and redirects to clean URL.
     */
    private function resolveUser(): ?array
    {
        // Valid local session?
        if ($this->hasValidLocalSession()) {
            return $_SESSION['_qsj_user'];
        }

        // Incoming ticket from Qui suis-je ?
        if (isset($_GET['qsj_ticket'])) {
            $ticket = (string)$_GET['qsj_ticket'];
            $user   = $this->validateTicket($ticket);
            if ($user !== null) {
                $this->storeLocalSession($user);
                // Strip ticket from URL and redirect (clean URL)
                header('Location: ' . $this->currentUrlWithout('qsj_ticket'));
                exit;
            }
            // Invalid ticket - fall through to treat as unauthenticated
        }

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