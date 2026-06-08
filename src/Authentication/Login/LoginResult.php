<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\Login;

use Infocyph\AuthLayer\Authentication\Session\AuthSession;
use Infocyph\AuthLayer\Principal\PrincipalInterface;

final readonly class LoginResult
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public LoginStatus $status,
        public ?PrincipalInterface $principal = null,
        public ?AuthSession $session = null,
        public ?string $code = null,
        public bool $rehashRecommended = false,
        public array $context = [],
    ) {}

    public function authenticated(): bool
    {
        return $this->status === LoginStatus::AUTHENTICATED;
    }

    public function failed(): bool
    {
        return !$this->successful();
    }

    public function successful(): bool
    {
        return $this->authenticated();
    }
}
