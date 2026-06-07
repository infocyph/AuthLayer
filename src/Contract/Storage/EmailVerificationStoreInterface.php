<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Contract\Storage;

use Infocyph\AuthLayer\Authentication\EmailVerification\EmailVerificationRequest;

interface EmailVerificationStoreInterface
{
    public function consume(string $requestId): void;

    public function find(string $requestId): ?EmailVerificationRequest;

    public function save(EmailVerificationRequest $request): void;
}
