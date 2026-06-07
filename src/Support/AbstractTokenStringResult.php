<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

abstract readonly class AbstractTokenStringResult extends AbstractCodeContextResult
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public ?string $token = null,
        ?string $code = null,
        array $context = [],
    ) {
        parent::__construct($code, $context);
    }
}
