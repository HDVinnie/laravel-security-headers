# laravel-security-headers
 Security related headers to HTTP responses in Laravel
 
 [ico-license]: https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square
[![Software License][ico-license]](LICENSE)
 [![Packagist](https://img.shields.io/packagist/v/hdvinnie/laravel-security-headers)](https://packagist.org/packages/hdvinnie/laravel-security-headers/)
[![Packagist Downloads](https://img.shields.io/packagist/dm/hdvinnie/laravel-security-headers.svg?label=packagist%20downloads)](https://packagist.org/packages/hdvinnie/laravel-security-headers)

## Installation

Install using composer

```sh
composer require hdvinnie/laravel-security-headers
```

Add service provider in `config/app.php` ( laravel version < 5.5 )

```php
HDVinnie\SecureHeaders\SecureHeadersServiceProvider::class,
```

Publish config file

```sh
php artisan vendor:publish --provider="HDVinnie\SecureHeaders\SecureHeadersServiceProvider"
```

Add global middleware in `app/Http/Kernel.php`

```php
\HDVinnie\SecureHeaders\SecureHeadersMiddleware::class,
```

Set up config file `config/secure-headers.php`

Done!
