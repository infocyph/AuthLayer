<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Account;

use Infocyph\AuthLayer\Support\HasEnumStatusResult;

final readonly class AccountResult
{
    use HasEnumStatusResult;

    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public AccountActionStatus $status,
        public ?AccountInterface $account = null,
        public ?string $code = null,
        public array $context = [],
    ) {}

    /**
     * @return list<object>
     */
    protected function successStatuses(): array
    {
        return [AccountActionStatus::CREATED, AccountActionStatus::UPDATED];
    }
}
