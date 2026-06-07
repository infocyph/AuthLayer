<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\EmailVerification;

use Infocyph\AuthLayer\Support\AbstractTokenStringResult;

final readonly class EmailVerificationResult extends AbstractTokenStringResult
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public EmailVerificationStatus $status,
        public ?EmailVerificationRequest $request = null,
        ?string $token = null,
        ?string $code = null,
        array $context = [],
    ) {
        parent::__construct($token, $code, $context);
    }

    public function email(): ?string
    {
        return $this->request?->email;
    }

    public function failed(): bool
    {
        return !$this->successful();
    }

    public function successful(): bool
    {
        return $this->status === EmailVerificationStatus::ISSUED
            || $this->status === EmailVerificationStatus::VERIFIED;
    }

    public function verified(): bool
    {
        return $this->status === EmailVerificationStatus::VERIFIED;
    }
}
