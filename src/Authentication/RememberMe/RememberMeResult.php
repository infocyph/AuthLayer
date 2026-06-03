<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\RememberMe;

final readonly class RememberMeResult
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public RememberTokenStatus $status,
        public ?RememberToken $token = null,
        public ?RememberTokenRecord $record = null,
        public ?string $code = null,
        public array $context = [],
    ) {
    }

    public function verified(): bool
    {
        return $this->status === RememberTokenStatus::VERIFIED;
    }
}
