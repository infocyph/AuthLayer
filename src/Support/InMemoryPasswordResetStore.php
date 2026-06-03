<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Authentication\PasswordReset\PasswordResetRequest;
use Infocyph\AuthLayer\Contract\Clock\ClockInterface;
use Infocyph\AuthLayer\Contract\Storage\PasswordResetStoreInterface;

final class InMemoryPasswordResetStore implements PasswordResetStoreInterface
{
    /**
     * @var array<string, PasswordResetRequest>
     */
    private array $requests = [];

    public function __construct(
        private readonly ClockInterface $clock = new SystemClock(),
    ) {
    }

    public function save(PasswordResetRequest $request): void
    {
        $this->requests[$request->id] = $request;
    }

    public function find(string $requestId): ?PasswordResetRequest
    {
        return $this->requests[$requestId] ?? null;
    }

    public function consume(string $requestId): void
    {
        $request = $this->requests[$requestId] ?? null;

        if ($request === null) {
            return;
        }

        $this->requests[$requestId] = new PasswordResetRequest(
            id: $request->id,
            accountId: $request->accountId,
            requestedAt: $request->requestedAt,
            expiresAt: $request->expiresAt,
            consumedAt: $this->clock->now(),
            context: $request->context,
        );
    }

    public function wasConsumed(string $requestId): bool
    {
        return ($this->requests[$requestId] ?? null)?->isConsumed() ?? false;
    }
}
