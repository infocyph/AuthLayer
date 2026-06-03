<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\Impersonation;

use Infocyph\AuthLayer\Principal\PrincipalInterface;

final readonly class ImpersonationResult
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public ?PrincipalInterface $principal = null,
        public ?ImpersonationSession $session = null,
        public ?string $code = null,
        public array $context = [],
    ) {
    }
}
