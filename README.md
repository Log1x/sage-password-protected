# Sage Password Protected

Sage Password Protected is a simple password protection package for use with [Sage 9](https://github.com/roots/sage) built for developers. No admin pages, no styles, no javascript, no bloat. Simply pass your own configuration to the provided filters and off you go. 

Easily build your own field group for it within your theme options using ACF, or pass a filter so it is only enabled when `WP_ENV` does not equal `production`.

## Requirements

* [Sage](https://github.com/roots/sage) >= 9.0
* [PHP](https://secure.php.net/manual/en/install.php) >= 7.0
* [Composer](https://getcomposer.org/download/)

## Installation 

Install via Composer:

```bash
composer require log1x/sage-password-protected
```

## Usage

Out of the box, this package does absolutely nothing as all values are defaulted to false. To get started, begin passing your values through the provided filters. When passing the password, you must either pass it through `password_hash()` or if using ACF, use my [acf-encrypted-password](https://github.com/log1x/acf-encrypted-password) field.

Below are not only the provided filters, but a personal example of how I use them alongside ACF and [ACF Fluent](https://github.com/samrap/acf-fluent).

### Filters

```php
/**
 * Returns true if password protection is enabled.
 *
 * @return boolean
 */
add_filter('password-protected/isActive', function () {
    return Acf::option('password_protected')->get();
});

/**
 * Returns the password set for password protection.
 *
 * @return string
 */
add_filter('password-protected/password', function () {
    return Acf::option('password')->get();
});

/**
 * Returns true if feeds are allowed while password protection is enabled.
 *
 * @return boolean
 */
add_filter('password-protected/allowFeeds', function () {
    return Acf::option('password_show_feeds')->get();
});

/**
 * Returns true if admins are allowed to bypass authentication while password protection is enabled.
 *
 * @return boolean
 */
add_filter('password-protected/allowAdmins', function () {
    return Acf::option('password_allow_administrators')->get();
});

/**
 * Returns true if users are allowed to bypass authentication while password protection is enabled.
 *
 * @return boolean
 */
add_filter('password-protected/allowUsers', function () {
    return Acf::option('password_allow_users')->get();
});

/**
 * Returns true if specific IP Addresses are allowed to bypass authentication while password protection is enabled.
 *
 * @return boolean
 */
add_filter('password-protected/allowIpAddresses', function () {
    return Acf::option('password_allow_by_ip_address')->get();
});

/**
 * Returns the IP addresses allowed to bypass authentication while password protection is enabled.
 *
 * @return array
 */
add_filter('password-protected/allowedIpAddresses', function () {
    return Acf::option('password_allowed_ip_addresses')->get();
});
```

You can also filter the page title:

```php
/**
 * Returns the page title used for the password protection page.
 *
 * @param  string $name
 * @return string
 */
add_filter('password-protected/title', function ($name) {
    return $name . ' | Protected';
});
```

### ACF Builder

If you happen to be utilizing ACF Builder, you can use my above filters along with:

```php
<?php

namespace App;

use StoutLogic\AcfBuilder\FieldsBuilder;

$config = (object) [
    'ui'      => 1,
    'wrapper' => ['width' => 30],
    'ip'      => $_SERVER['X-Forwarded-For'] ?? $_SERVER['REMOTE_ADDR'],
];

$password = new FieldsBuilder('password_protected');

$password
    ->addTab('password_protected', ['placement' => 'left']);

$password
    ->addTrueFalse('password_protected', ['ui' => $config->ui])
        ->setInstructions('Enable site-wide password protection?')

    ->addField('password', 'encrypted_password', ['wrapper' => $config->wrapper])
        ->setInstructions('Enter the login password.')
        ->conditional('password_protected', '==', '1')

    ->addTrueFalse('password_show_feeds', ['label' => 'Show Feeds?', 'ui' => $config->ui])
        ->setInstructions('Enable RSS Feeds without a password?')
        ->conditional('password_protected', '==', '1')

    ->addTrueFalse('password_allow_ip_address', ['label' => 'Allow by IP Address', 'ui' => $config->ui])
        ->setInstructions('Enable whitelisting users by their IP Address.')
        ->conditional('password_protected', '==', '1')

    ->addRepeater('password_allowed_ip_addresses', ['label' => 'Allowed IP Addresses', 'button_label' => 'Add IP Address'])
        ->conditional('password_protected', '==', '1')
            ->and('password_allow_ip_address', '==', '1')
        ->setInstructions('Current IP Address: ' . $config->ip)

        ->addText('ip_address', ['label' => 'IP Address', 'placeholder' => $config->ip])
            ->setInstructions('The IP Address of the user to allow through password protection.')

        ->addText('ip_address_comment', ['label' => 'Comment', 'placeholder' => 'John Doe\'s Home'])
            ->setInstructions('A comment containing an identifier for this IP address. This is strictly for organization purposes.')
    ->endRepeater()

    ->addTrueFalse('password_allow_users', ['ui' => $config->ui])
        ->setInstructions('Allow bypassing password protection while logged in as a user.')
        ->conditional('password_protected', '==', '1')

    ->addTrueFalse('password_allow_administrators', ['ui' => $config->ui])
        ->conditional('password_protected', '==', '1')
            ->and('password_allow_users', '==', '0')
        ->setInstructions('Allow bypassing password protection while logged in as an administrator.');

return $password;
```

## Security

Obviously the cookie isn't absolutely foolproof, my default hash being passed to `openssl_encrypt()` is laughable, and storing the encrypted password md5'd as the hash is laughable– but let's be real, this is a simple password protection package to protect your front-facing site during things such as staging (to prevent webcrawling), maintenance, etc. and I personally believe the effort I put into place is **extremely** overkill as is.

## Contributing

Any contributions are appreciated. There are still some things left untouched such as the ability to customize the cookie hash, filtering the Blade view location, etc.

:heart:
