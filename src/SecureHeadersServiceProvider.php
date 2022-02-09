<?php

namespace HDVinnie\SecureHeaders;

use Illuminate\Support\ServiceProvider;
use Laravel\Lumen\Application;

class SecureHeadersServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application events.
     */
    public function boot(): void
    {
        if ($this->app instanceof Application) {
            $this->bootLumen();
        } else {
            $this->bootLaravel();
        }
    }

    /**
     * Bootstrap laravel application events.
     */
    protected function bootLaravel(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                $this->configPath() => config_path('secure-headers.php'),
            ], 'config');
        }
    }

    /**
     * Bootstrap lumen application events.
     */
    protected function bootLumen(): void
    {
        $this->app->configure('secure-headers');
    }

    /**
     * Register the service provider.
     */
    public function register(): void
    {
        $this->mergeConfigFrom($this->configPath(), 'secure-headers');
    }

    /**
     * Get config file path.
     */
    protected function configPath(): string
    {
        return __DIR__ . '/../config/secure-headers.php';
    }
}
