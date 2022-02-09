<?php

namespace HDVinnie\SecureHeaders;

use HDVinnie\SecureHeaders\Builders\ClearSiteDataBuilder;
use HDVinnie\SecureHeaders\Builders\ContentSecurityPolicyBuilder;
use HDVinnie\SecureHeaders\Builders\ExceptCTBuilder;
use HDVinnie\SecureHeaders\Builders\PermissionsPolicyBuilder;
use HDVinnie\SecureHeaders\Builders\StrictTransportSecurityBuilder;
use Exception;
use InvalidArgumentException;
use RuntimeException;

class SecureHeaders
{
    private $config;

    /**
     * Determine header had sent or not.
     */
    protected bool $sent = false;

    /**
     * Nonces for `script-src` and `style-src`.
     */
    protected static array $nonces = [
        'script' => [],
        'style' => [],
    ];

    /**
     * Constructor.
     */
    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    /**
     * Destructor.
     */
    public function __destruct()
    {
        if ($this->sent) {
            self::$nonces['script'] = self::$nonces['style'] = [];
        }
    }

    /**
     * Load data from file.
     */
    public static function fromFile($file): SecureHeaders
    {
        if (!is_file($file)) {
            throw new InvalidArgumentException(
                sprintf('%s does not exist.', $file)
            );
        }

        $config = require $file;

        return new self($config);
    }

    /**
     *  Send HTTP headers.
     */
    public function send(): void
    {
        if (headers_sent($file, $line)) {
            throw new RuntimeException(
                sprintf('Headers already sent in %s on line %d.', $file, $line)
            );
        }

        foreach ($this->headers() as $key => $value) {
            header(sprintf('%s: %s', $key, $value), true);
        }

        $this->sent = true;
    }

    /**
     * Get HTTP headers.
     */
    public function headers(): array
    {
        $headers = array_merge(
            $this->csp(),
            $this->permissionsPolicy(),
            $this->hsts(),
            $this->expectCT(),
            $this->clearSiteData(),
            $this->miscellaneous()
        );

        $this->sent = true;

        return array_filter($headers);
    }

    /**
     * Get CSP header.
     */
    protected function csp(): array
    {
        $config = $this->config['csp'] ?? [];

        if (!($config['enable'] ?? false)) {
            return [];
        }

        $config['script-src']['nonces'] = self::$nonces['script'];

        $config['style-src']['nonces'] = self::$nonces['style'];

        $key = ($config['report-only'] ?? false)
            ? 'Content-Security-Policy-Report-Only'
            : 'Content-Security-Policy';

        $builder = new ContentSecurityPolicyBuilder($config);

        return [$key => $builder->get()];
    }

    /**
     * Get Permissions Policy header.
     */
    protected function permissionsPolicy(): array
    {
        $config = $this->config['permissions-policy'] ?? [];

        if (!($config['enable'] ?? false)) {
            return [];
        }

        $builder = new PermissionsPolicyBuilder($config);

        return ['Permissions-Policy' => $builder->get()];
    }

    /**
     * Get HSTS header.
     */
    protected function hsts(): array
    {
        $config = $this->config['hsts'] ?? [];

        if (!($config['enable'] ?? false)) {
            return [];
        }

        $builder = new StrictTransportSecurityBuilder($config);

        return ['Strict-Transport-Security' => $builder->get()];
    }

    /**
     * Generate Expect-CT header.
     */
    protected function expectCT(): array
    {
        $config = $this->config['expect-ct'] ?? [];

        if (!($config['enable'] ?? false)) {
            return [];
        }

        $builder = new ExceptCTBuilder($config);

        return ['Expect-CT' => $builder->get()];
    }

    /**
     * Generate Clear-Site-Data header.
     */
    protected function clearSiteData(): array
    {
        $config = $this->config['clear-site-data'] ?? [];

        if (!($config['enable'] ?? false)) {
            return [];
        }

        $builder = new ClearSiteDataBuilder($config);

        return ['Clear-Site-Data' => $builder->get()];
    }

    /**
     * Get miscellaneous headers.
     */
    protected function miscellaneous(): array
    {
        return array_filter([
            'X-Content-Type-Options' => $this->config['x-content-type-options'],
            'X-Download-Options' => $this->config['x-download-options'],
            'X-Frame-Options' => $this->config['x-frame-options'],
            'X-Permitted-Cross-Domain-Policies' => $this->config['x-permitted-cross-domain-policies'],
            'X-Powered-By' => $this->config['x-powered-by'] ?? ($this->config['x-power-by'] ?? ''),
            'X-XSS-Protection' => $this->config['x-xss-protection'],
            'Referrer-Policy' => $this->config['referrer-policy'],
            'Server' => $this->config['server'],
        ]);
    }

    /**
     * Generate random nonce value for current request.
     *
     * @throws Exception
     */
    public static function nonce(string $target = 'script'): string
    {
        $nonce = base64_encode(bin2hex(random_bytes(8)));

        self::$nonces[$target][] = $nonce;

        return $nonce;
    }
}
