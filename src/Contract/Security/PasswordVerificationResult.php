<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Contract\Security;

final readonly class PasswordVerificationResult
{
    public function __construct(
        public bool $verified,
        public bool $needsRehash = false,
        public ?string $rehash = null,
    ) {}
}
