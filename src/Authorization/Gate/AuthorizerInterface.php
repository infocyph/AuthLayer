<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Gate;

use Infocyph\AuthLayer\Authorization\Decision\AuthorizationDecision;
use Infocyph\AuthLayer\Principal\PrincipalInterface;

interface AuthorizerInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function can(
        PrincipalInterface $principal,
        string $ability,
        mixed $resource = null,
        array $context = [],
    ): AuthorizationDecision;

    /**
     * @param array<string, mixed> $context
     */
    public function authorize(
        PrincipalInterface $principal,
        string $ability,
        mixed $resource = null,
        array $context = [],
    ): void;
}
