<?php

namespace HDVinnie\SecureHeaders\Builders;

abstract class Builder
{
    /**
     * Builder config.
     */
    protected array $config = [];

    /**
     * Builder constructor.
     */
    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    /**
     * Get result.
     */
    abstract public function get(): string;
}
