<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\PasswordChange;

use Infocyph\AuthLayer\Support\HasEnumStatusResult;

final readonly class PasswordChangeResult
{
    use HasEnumStatusResult;

    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public PasswordChangeStatus $status,
        public ?string $code = null,
        public array $context = [],
    ) {}

    /**
     * @return list<object>
     */
    protected function successStatuses(): array
    {
        return [PasswordChangeStatus::CHANGED];
    }
}
