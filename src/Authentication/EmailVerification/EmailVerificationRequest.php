<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\EmailVerification;

final readonly class EmailVerificationRequest
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public string $id,
        public string $accountId,
        public string $email,
        public int $requestedAt,
        public int $expiresAt,
        public ?int $consumedAt = null,
        public array $context = [],
    ) {
    }

    public function isConsumed(): bool
    {
        return $this->consumedAt !== null;
    }

    public function isExpiredAt(?int $timestamp = null): bool
    {
        return $this->expiresAt <= ($timestamp ?? time());
    }
}
