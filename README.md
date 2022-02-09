# laravel-security-headers
 Security related headers to HTTP responses in Laravel

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
