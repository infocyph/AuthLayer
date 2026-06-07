<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\PasswordReset;

use Infocyph\AuthLayer\Support\AbstractTokenStringResult;
use Infocyph\AuthLayer\Support\HasEnumStatusResult;

final readonly class PasswordResetResult extends AbstractTokenStringResult
{
    use HasEnumStatusResult;

    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public PasswordResetStatus $status,
        public ?PasswordResetRequest $request = null,
        ?string $token = null,
        ?string $code = null,
        array $context = [],
    ) {
        parent::__construct($token, $code, $context);
    }

    public function completed(): bool
    {
        return $this->status === PasswordResetStatus::COMPLETED;
    }

    /**
     * @return list<object>
     */
    protected function successStatuses(): array
    {
        return [PasswordResetStatus::REQUESTED, PasswordResetStatus::COMPLETED];
    }
}
