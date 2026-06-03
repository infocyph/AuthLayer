<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\PasswordChange;

final readonly class PasswordChangeResult
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public PasswordChangeStatus $status,
        public ?string $code = null,
        public array $context = [],
    ) {
    }
}
