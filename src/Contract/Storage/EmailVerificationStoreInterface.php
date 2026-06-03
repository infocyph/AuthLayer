<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Contract\Storage;

use Infocyph\AuthLayer\Authentication\EmailVerification\EmailVerificationRequest;

interface EmailVerificationStoreInterface
{
    public function save(EmailVerificationRequest $request): void;

    public function find(string $requestId): ?EmailVerificationRequest;

    public function consume(string $requestId): void;
}
