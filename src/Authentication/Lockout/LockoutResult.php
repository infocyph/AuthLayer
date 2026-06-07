<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\Lockout;

use Infocyph\AuthLayer\Contract\Storage\LockoutReason;
use Infocyph\AuthLayer\Support\HasEnumStatusResult;

final readonly class LockoutResult
{
    use HasEnumStatusResult;

    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public LockoutStatus $status,
        public string $accountId,
        public ?LockoutReason $reason = null,
        public ?int $lockedUntil = null,
        public ?int $attempts = null,
        public ?string $code = null,
        public array $context = [],
    ) {}

    /**
     * @return list<object>
     */
    protected function successStatuses(): array
    {
        return [
            LockoutStatus::FAILURE_RECORDED,
            LockoutStatus::LOCKED,
            LockoutStatus::UNLOCKED,
            LockoutStatus::CLEAR,
        ];
    }
}
