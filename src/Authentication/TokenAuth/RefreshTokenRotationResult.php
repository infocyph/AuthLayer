<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\TokenAuth;

final readonly class RefreshTokenRotationResult
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public bool $rotated,
        public ?string $token = null,
        public ?RefreshTokenRecord $record = null,
        public ?string $code = null,
        public array $context = [],
    ) {
    }
}
