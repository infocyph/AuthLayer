<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\Passwordless;

use Infocyph\AuthLayer\Contract\Security\TokenVerificationResult;

final readonly class PasswordlessResult
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public PasswordlessStatus $status,
        public ?string $token = null,
        public ?TokenVerificationResult $verification = null,
        public ?string $code = null,
        public array $context = [],
    ) {
    }
}
