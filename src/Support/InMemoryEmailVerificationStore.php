<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Authentication\EmailVerification\EmailVerificationRequest;
use Infocyph\AuthLayer\Contract\Clock\ClockInterface;
use Infocyph\AuthLayer\Contract\Storage\EmailVerificationStoreInterface;

final class InMemoryEmailVerificationStore implements EmailVerificationStoreInterface
{
    /**
     * @var array<string, EmailVerificationRequest>
     */
    private array $requests = [];

    public function __construct(
        private readonly ClockInterface $clock = new SystemClock(),
    ) {
    }

    public function save(EmailVerificationRequest $request): void
    {
        $this->requests[$request->id] = $request;
    }

    public function find(string $requestId): ?EmailVerificationRequest
    {
        return $this->requests[$requestId] ?? null;
    }

    public function consume(string $requestId): void
    {
        $request = $this->requests[$requestId] ?? null;

        if ($request === null) {
            return;
        }

        $this->requests[$requestId] = new EmailVerificationRequest(
            id: $request->id,
            accountId: $request->accountId,
            email: $request->email,
            requestedAt: $request->requestedAt,
            expiresAt: $request->expiresAt,
            consumedAt: $this->clock->now(),
            context: $request->context,
        );
    }
}
