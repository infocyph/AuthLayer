<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Contract\Security\PasswordPolicyInterface;
use Infocyph\AuthLayer\Contract\Security\PasswordPolicyResult;

final class AcceptAllPasswordPolicy implements PasswordPolicyInterface
{
    public function validate(string $plainPassword, array $context = []): PasswordPolicyResult
    {
        unset($plainPassword, $context);

        return new PasswordPolicyResult(true);
    }
}
