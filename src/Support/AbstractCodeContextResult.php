<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

abstract readonly class AbstractCodeContextResult
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public ?string $code = null,
        public array $context = [],
    ) {}
}
