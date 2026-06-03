<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Account;

final readonly class AccountResult
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public AccountActionStatus $status,
        public ?AccountInterface $account = null,
        public ?string $code = null,
        public array $context = [],
    ) {
    }
}
