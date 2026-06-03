<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Policy;

use Infocyph\AuthLayer\Authorization\Decision\AuthorizationDecision;
use Infocyph\AuthLayer\Principal\PrincipalInterface;

interface PolicyInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function authorize(
        PrincipalInterface $principal,
        string $ability,
        mixed $resource = null,
        array $context = [],
    ): AuthorizationDecision|bool|null;
}
