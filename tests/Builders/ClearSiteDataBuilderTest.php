<?php

namespace HDVinnie\SecureHeaders\Tests\Builders;

use HDVinnie\SecureHeaders\Builders\ClearSiteDataBuilder;
use HDVinnie\SecureHeaders\Tests\TestCase;

final class ClearSiteDataBuilderTest extends TestCase
{
    public function testClearSiteData()
    {
        $config = [];

        $this->assertSame(
            '',
            (new ClearSiteDataBuilder($config))->get()
        );

        $config = [
            'all' => true,
        ];

        $this->assertSame(
            '"*"',
            (new ClearSiteDataBuilder($config))->get()
        );

        $config = [
            'cache' => true,

            'storage' => true,
        ];

        $this->assertSame(
            '"cache", "storage"',
            (new ClearSiteDataBuilder($config))->get()
        );

        $config = [
            'executionContexts' => true,
        ];

        $this->assertSame(
            '"executionContexts"',
            (new ClearSiteDataBuilder($config))->get()
        );
    }
}
