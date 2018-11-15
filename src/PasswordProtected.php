<?php

namespace App\PasswordProtected;

/**
 * Return if Password Protected already exists.
 */
if (class_exists('PasswordProtected')) {
    return;
}

/**
 * Password Protected
 */
class PasswordProtected
{
    /**
     * Cookie Name
     *
     * @var string
     */
    protected $cookie = '_password_protected';

    /**
     * Cipher Method
     *
     * @var string
     */
    protected $cipher = 'AES-256-CBC';

    /**
     * Initialization Vector
     *
     * @var string
     */
    protected $vector = '1234567812345678';

    /**
     * Secret Token
     *
     * @var string
     */
    protected $secret = '_this_is_very_secure';

    /**
     * Constructor
     */
    public function __construct()
    {
        /** Return if Sage is not present. */
        if (!function_exists('App\sage')) {
            return;
        }

        /** Hooks */
        add_action('init', [$this, 'disableCaching'], 1);
        add_action('init', [$this, 'processLogin'], 1);
        add_action('wp', [$this, 'disableFeeds']);
        add_action('template_redirect', [$this, 'showLogin'], -1);

        /** Configuration */
        $this->defaults = [
            'active'             => false,
            'password'           => false,
            'secret'             => $this->secret,
            'allowFeeds'         => false,
            'allowAdmins'        => false,
            'allowUsers'         => false,
            'allowIpAddresses'   => false,
            'allowedIpAddresses' => [],
            'title'              => $this->name()
        ];

        $this->config = (object) wp_parse_args(apply_filters('password_protected', []), $this->defaults);

        /** Initialize WP_Error */
        $this->errors = new \WP_Error();
    }

    /**
     * Show login if password protect is active and user is not already authorized.
     *
     * @return void
     */
    public function showLogin()
    {
        if (!$this->isActive() || $this->isAllowed()) {
            return;
        }

        if (isset($_REQUEST['password_protected']) && $_REQUEST['password_protected'] == 'login') {
            echo \App\template(__DIR__.'/views/password-protected.blade.php', [
                'password' => $this
            ]);

            exit();
        }

        if (wp_safe_redirect($this->requestUrl())) {
            exit();
        }
    }

    /**
     * Attempt to authorize and process the user's login with the specified password.
     *
     * @return void
     */
    public function processLogin()
    {
        if ($this->isActive() && !empty($_REQUEST['password'])) {
            if ($this->verifyPassword($_REQUEST['password'])) {
                $this->setCookie();

                if (wp_safe_redirect($this->redirectUrl())) {
                    exit;
                }

                return;
            }

            $this->unsetCookie();
            $this->errors->add('invalid_password', __('The password you have entered is incorrect.', 'app'));
        }
    }

    /**
     * Returns true if password protect is enabled.
     *
     * @return boolean
     */
    public function isActive()
    {
        if ($this->config->active) {
            return is_robots() ? false : true;
        }

        return false;
    }

    /**
     * Disables page caching while password protect is active.
     *
     * @return void
     */
    public function disableCaching()
    {
        if ($this->isActive() && !defined('DONOTCACHEPAGE')) {
            define('DONOTCACHEPAGE', true);
        }
    }

    /**
     * Disables feeds if they are not explicitly enabled while password protection is active.
     *
     * @return void
     */
    public function disableFeeds()
    {
        if ($this->isActive() && !$this->allowFeeds()) {
            return collect([
                'do_feed',
                'do_feed_rdf',
                'do_feed_rss',
                'do_feed_rss2',
                'do_feed_atom'
            ])->map(function ($feed) {
                return add_action($feed, function () {
                    wp_die(sprintf(__('Feeds are not available for this site. Please visit the <a href="%s">website</a>.', 'app'), get_bloginfo('url')));
                }, 1);
            });
        }
    }

    /**
     * Returns true if feeds are allowed during password protection.
     *
     * @return boolean
     */
    protected function allowFeeds()
    {
        if ($this->config->allowFeeds && is_feed()) {
            return true;
        }

        return false;
    }

    /**
     * Returns true if administrators are allowed to bypass password protection
     * and current user is deemed an administrator.
     *
     * @return boolean
     */
    protected function allowAdmins()
    {
        if (!is_admin() && $this->config->allowAdmins && current_user_can('manage_options')) {
            return true;
        }

        return false;
    }

    /**
     * Returns true if users are allowed to bypass password protection
     * and current user is logged in.
     *
     * @return boolean
     */
    protected function allowUsers()
    {
        if (!is_admin() && $this->config->allowUsers && is_user_logged_in()) {
            return true;
        }

        return false;
    }

    /**
     * Returns true if the current users IP address is permitted to bypass password protection.
     *
     * @return boolean
     */
    protected function allowedIpAddress()
    {
        if ($this->config->allowIpAddresses && is_array($this->getAllowedIpAddresses())) {
            if (in_array($_SERVER['REMOTE_ADDR'], $this->getAllowedIpAddresses())) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns the allowed IP Addresses.
     *
     * @return array
     */
    protected function getAllowedIpAddresses()
    {
        return collect($this->config->allowedIpAddresses)
            ->map(function ($address) {
                return collect($address)
                    ->filter()
                    ->pop();
            })->filter()->toArray();
    }

    /**
     * Returns true if the user is allowed access.
     *
     * @return boolean
     */
    protected function isAllowed()
    {
        if ($this->verifyCookie() || $this->allowAdmins() || $this->allowUsers() || $this->allowedIpAddress()) {
            return true;
        }

        return false;
    }

    /**
     * Returns the current hashed password.
     *
     * @return string
     */
    protected function getPassword()
    {
        return $this->config->password;
    }

    /**
     * Returns true if the specified password is correct.
     *
     * @param  string $password
     * @return boolean
     */
    protected function verifyPassword($password)
    {
        return password_verify($password, $this->getPassword());
    }

    /**
     * Returns the hash value.
     *
     * @return string
     */
    protected function getHash()
    {
        return md5($this->getPassword());
    }

    /**
     * Returns the login page URL.
     *
     * @return string
     */
    protected function loginUrl()
    {
        return add_query_arg('password_protected', 'login', $this->url());
    }

    /**
     * Returns the redirect URL.
     *
     * @return string
     */
    public function redirectUrl()
    {
        return !empty($_REQUEST['redirect_to']) && $_REQUEST['redirect_to'] !== '/' ? $_REQUEST['redirect_to'] : $this->url();
    }

    /**
     * Returns the inital requested URL.
     *
     * @return string
     */
    protected function requestUrl()
    {
        if (!empty($_SERVER['REQUEST_URI']) && $_SERVER['REQUEST_URI'] !== '/') {
            $request = (is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        }

        return add_query_arg('redirect_to', urlencode($request ?? $this->url()), $this->loginUrl());
    }

    /**
     * Returns the blog title.
     *
     * @return string
     */
    public function name()
    {
        return get_bloginfo('name');
    }

    /**
     * Returns the blog URL.
     *
     * @return string
     */
    public function url()
    {
        return get_home_url('/');
    }

    /**
     * Returns the page title used on the password protected page.
     *
     * @return string
     */
    public function title()
    {
        return $this->config->title;
    }

    /**
     * Returns the users IP Address.
     *
     * @return string
     */
    protected function ipAddress()
    {
        return $_SERVER['X-Forwarded-For'] ?? $_SERVER['REMOTE_ADDR'];
    }

    /**
     * Returns the users browser agent.
     *
     * @return string
     */
    protected function browserAgent()
    {
        return $_SERVER['HTTP_USER_AGENT'];
    }

    /**
     * Returns the auth cookie contents.
     *
     * @return string
     */
    protected function getCookie()
    {
        return $_COOKIE[$this->cookie] ?? false;
    }

    /**
     * Encrypts the auth cookie and sets it.
     *
     * @return void
     */
    protected function setCookie()
    {
        $cookie = openssl_encrypt(json_encode([
            'expires' => $this->getCookieDuration(),
            'hash'    => $this->getHash(),
            'ip'      => $this->ipAddress() ?? false,
            'agent'   => $this->browserAgent() ?? false
        ]), $this->cipher, $this->secret, false, $this->vector);

        return setcookie($this->cookie, $cookie, $this->getCookieDuration(), COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
    }

    /**
     * Removes the auth cookie if it is set.
     *
     * @return void
     */
    protected function unsetCookie()
    {
        return setcookie($this->cookie, '', -1, COOKIEPATH, COOKIE_DOMAIN);
    }

    /**
     * Verifies the auth cookie if it is set.
     *
     * @return boolean
     */
    protected function verifyCookie()
    {
        if (!$this->parseCookie() || $this->parseCookie()->expires < current_time('timestamp')) {
            return false;
        }

        if ($this->parseCookie()->hash !== $this->getHash()) {
            return false;
        }

        return true;
    }

    /**
     * Decrypts our auth cookie payload if it is set.
     *
     * @return array
     */
    protected function parseCookie()
    {
        if (!$cookie = openssl_decrypt($this->getCookie(), $this->cipher, $this->config->secret, false, $this->vector)) {
            return false;
        }

        return (object) json_decode($cookie, true);
    }

    /**
     * Returns the expiration age for the auth cookie.
     *
     * @param  integer $days
     * @return integer
     */
    protected function getCookieDuration($days = 1)
    {
        return current_time('timestamp') + (86400 * $days);
    }
}

/**
 * Initalize with after_setup_theme to assure Sage is loaded.
 */
if (function_exists('add_action')) {
    add_action('after_setup_theme', function () {
        return new PasswordProtected();
    }, 20);
}
