<?php

namespace HDVinnie\SecureHeaders\Builders;

final class StrictTransportSecurityBuilder extends Builder
{
    public function get(): string
    {
        $directives[] = $this->maxAge();

        if ($this->config['include-sub-domains'] ?? false) {
            $directives[] = 'includeSubDomains';
        }

        if ($this->config['preload'] ?? false) {
            $directives[] = 'preload';
        }

        return implode('; ', $directives);
    }

    /**
     * Get max-age directive.
     */
    public function maxAge(): string
    {
        $origin = $this->config['max-age'] ?? 31536000;

        // convert to int
        $age = (int)$origin;

        // prevent negative value
        $val = max($age, 0);

        return sprintf('max-age=%d', $val);
    }
}
