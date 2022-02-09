<?php

namespace HDVinnie\SecureHeaders\Builders;

final class ContentSecurityPolicyBuilder extends Builder
{
    /**
     * Content Security Policy whitelist directives.
     */
    protected array $whitelist = [
        'base-uri' => true,
        'child-src' => true,
        'connect-src' => true,
        'default-src' => true,
        'font-src' => true,
        'form-action' => true,
        'frame-ancestors' => true,
        'frame-src' => true,
        'img-src' => true,
        'manifest-src' => true,
        'media-src' => true,
        'navigate-to' => true,
        'object-src' => true,
        'prefetch-src' => true,
        'script-src' => true,
        'script-src-attr' => true,
        'script-src-elem' => true,
        'style-src' => true,
        'style-src-attr' => true,
        'style-src-elem' => true,
        'worker-src' => true,
    ];

    public function get(): string
    {
        $builds = [
            $this->directives(),
            $this->pluginTypes(),
            $this->sandbox(),
            $this->requireTrustedTypesFor(),
            $this->trustedTypes(),
            $this->blockAllMixedContent(),
            $this->upgradeInsecureRequests(),
            $this->reportTo(),
            $this->reportUri(),
        ];

        return $this->implode(array_filter($builds), '; ');
    }

    /**
     * Build directives.
     */
    protected function directives(): string
    {
        $result = [];

        foreach ($this->config as $name => $config) {
            if (!($this->whitelist[$name] ?? false)) {
                continue;
            }

            if (empty($val = $this->directive($config))) {
                continue;
            }

            $result[] = sprintf('%s %s', $name, $val);
        }

        return $this->implode($result, '; ');
    }

    /**
     * Build directive.
     */
    public function directive(array $config): string
    {
        if ($config['none'] ?? false) {
            return "'none'";
        }

        $sources = array_merge(
            $this->keywords($config),
            $this->schemes($config['schemes'] ?? []),
            $this->hashes($config['hashes'] ?? []),
            $this->nonces($config['nonces'] ?? []),
            $config['allow'] ?? []
        );

        $filtered = array_filter($sources);

        return $this->implode($filtered);
    }

    /**
     * Build directive keywords.
     */
    public function keywords(array $config): array
    {
        $whitelist = [
            'self' => true,
            'unsafe-inline' => true,
            'unsafe-eval' => true,
            'unsafe-hashes' => true,
            'strict-dynamic' => true,
            'report-sample' => true,
            'unsafe-allow-redirects' => true,
        ];

        $passes = $this->filter($config, $whitelist);

        return array_map(function (string $keyword) {
            return sprintf("'%s'", $keyword);
        }, $passes);
    }

    /**
     * Build directive schemes.
     */
    public function schemes(array $schemes): array
    {
        return array_map(function (string $scheme) {
            $trimmed = trim($scheme);

            if (substr($trimmed, -1) === ':') {
                return $trimmed;
            }

            return sprintf('%s:', $trimmed);
        }, $schemes);
    }

    /**
     * Build directive nonces.
     */
    public function nonces(array $nonces): array
    {
        return array_map(function (string $nonce) {
            $trimmed = trim($nonce);

            if (base64_decode($trimmed, true) === false) {
                return '';
            }

            return sprintf("'nonce-%s'", $trimmed);
        }, $nonces);
    }

    /**
     * Build directive hashes.
     */
    public function hashes(array $groups): array
    {
        $result = [];

        foreach ($groups as $hash => $items) {
            if (!in_array($hash, ['sha256', 'sha384', 'sha512'], true)) {
                continue;
            }

            foreach ($items as $item) {
                $trimmed = trim($item);

                if (base64_decode($trimmed, true) === false) {
                    continue;
                }

                $result[] = sprintf("'%s-%s'", $hash, $trimmed);
            }
        }

        return $result;
    }

    /**
     * Build plugin-types directive.
     */
    public function pluginTypes(): string
    {
        $pluginTypes = $this->config['plugin-types'] ?? [];

        $passes = array_filter($pluginTypes, function (string $mime) {
            return preg_match('/^[a-z\-]+\/[a-z\-]+$/i', $mime);
        });

        if (!empty($passes)) {
            array_unshift($passes, 'plugin-types');
        }

        return $this->implode($passes);
    }

    /**
     * Build sandbox directive.
     */
    public function sandbox(): string
    {
        $sandbox = $this->config['sandbox'] ?? [];

        if (!($sandbox['enable'] ?? false)) {
            return '';
        }

        $whitelist = [
            'allow-downloads-without-user-activation' => true,
            'allow-forms' => true,
            'allow-modals' => true,
            'allow-orientation-lock' => true,
            'allow-pointer-lock' => true,
            'allow-popups' => true,
            'allow-popups-to-escape-sandbox' => true,
            'allow-presentation' => true,
            'allow-same-origin' => true,
            'allow-scripts' => true,
            'allow-storage-access-by-user-activation' => true,
            'allow-top-navigation' => true,
            'allow-top-navigation-by-user-activation' => true,
        ];

        $passes = $this->filter($sandbox, $whitelist);

        array_unshift($passes, 'sandbox');

        return $this->implode($passes);
    }

    /**
     * Build require-trusted-types-for directive.
     */
    public function requireTrustedTypesFor(): string
    {
        $config = $this->config['require-trusted-types-for'] ?? [];

        if (!($config['script'] ?? false)) {
            return '';
        }

        return "require-trusted-types-for 'script'";
    }

    /**
     * Build trusted-types directive.
     */
    public function trustedTypes(): string
    {
        $trustedTypes = $this->config['trusted-types'] ?? [];

        if (!($trustedTypes['enable'] ?? false)) {
            return '';
        }

        $policies = array_map('trim', $trustedTypes['policies'] ?? []);

        if ($trustedTypes['default'] ?? false) {
            $policies[] = 'default';
        }

        if ($trustedTypes['allow-duplicates'] ?? false) {
            $policies[] = "'allow-duplicates'";
        }

        array_unshift($policies, 'trusted-types');

        return $this->implode($policies);
    }

    /**
     * Build block-all-mixed-content directive.
     */
    public function blockAllMixedContent(): string
    {
        if (!($this->config['block-all-mixed-content'] ?? false)) {
            return '';
        }

        return 'block-all-mixed-content';
    }

    /**
     * Build upgrade-insecure-requests directive.
     */
    public function upgradeInsecureRequests(): string
    {
        if (!($this->config['upgrade-insecure-requests'] ?? false)) {
            return '';
        }

        return 'upgrade-insecure-requests';
    }

    /**
     * Build report-to directive.
     */
    public function reportTo(): string
    {
        if (empty($this->config['report-to'])) {
            return '';
        }

        return sprintf('report-to %s', $this->config['report-to']);
    }

    /**
     * Build report-uri directive.
     */
    public function reportUri(): string
    {
        if (empty($this->config['report-uri'])) {
            return '';
        }

        $uri = $this->implode($this->config['report-uri']);

        return sprintf('report-uri %s', $uri);
    }

    /**
     * Using key to filter config and return keys.
     */
    public function filter(array $config, array $available): array
    {
        $targets = array_intersect_key($config, $available);

        $needs = array_filter($targets);

        return array_keys($needs);
    }

    /**
     * Implode strings using glue.
     */
    public function implode(array $payload, string $glue = ' '): string
    {
        return implode($glue, $payload);
    }
}
