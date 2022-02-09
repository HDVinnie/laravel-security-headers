<?php

namespace HDVinnie\SecureHeaders\Builders;

final class ExceptCTBuilder extends Builder
{
    /**
     * Max age max value.
     */
    public int $max = 2147483648;
    
    public function get(): string
    {
        $directives[] = $this->maxAge();

        if ($this->config['enforce'] ?? false) {
            $directives[] = 'enforce';
        }

        if (!empty($this->config['report-uri'])) {
            $directives[] = $this->reportUri();
        }

        return implode(', ', array_filter($directives));
    }

    /**
     * Get max-age directive.
     */
    public function maxAge(): string
    {
        $origin = $this->config['max-age'] ?? $this->max;

        // convert to int
        $age = intval($origin);

        // prevent negative value
        $val = max($age, 0);

        return sprintf('max-age=%d', $val);
    }

    /**
     * Get report-uri directive.
     */
    public function reportUri(): string
    {
        $uri = filter_var($this->config['report-uri'], FILTER_VALIDATE_URL);

        if ($uri === false) {
            return '';
        }

        return sprintf('report-uri="%s"', $uri);
    }
}
