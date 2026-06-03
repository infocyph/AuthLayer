<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\TokenAuth;

final readonly class TokenRevocationResult
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public TokenRevocationStatus $status,
        public string $familyId,
        public ?string $code = null,
        public array $context = [],
    ) {
    }
}
