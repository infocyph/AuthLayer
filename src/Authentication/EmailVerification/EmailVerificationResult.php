<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\EmailVerification;

final readonly class EmailVerificationResult
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public EmailVerificationStatus $status,
        public ?EmailVerificationRequest $request = null,
        public ?string $token = null,
        public ?string $code = null,
        public array $context = [],
    ) {
    }

    public function verified(): bool
    {
        return $this->status === EmailVerificationStatus::VERIFIED;
    }
}
