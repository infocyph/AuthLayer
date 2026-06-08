<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Authentication\EmailVerification\EmailVerificationRequest;
use Infocyph\AuthLayer\Contract\Storage\EmailVerificationStoreInterface;

final class InMemoryEmailVerificationStore extends AbstractInMemoryConsumableStore implements EmailVerificationStoreInterface
{
    public function consume(string $requestId): void
    {
        $storedRequestId = $requestId;
        $this->consumeStored($storedRequestId);
    }

    public function find(string $requestId): ?EmailVerificationRequest
    {
        $request = $this->findStored($requestId);

        if (!$request instanceof EmailVerificationRequest) {
            return null;
        }

        return $request;
    }

    public function save(EmailVerificationRequest $request): void
    {
        $this->saveStored($request, requestId: $request->id);
    }

    protected function consumeRequest(object $request, int $consumedAt): object
    {
        return $request instanceof EmailVerificationRequest ? $request->withConsumedAt($consumedAt) : $request;
    }
}
