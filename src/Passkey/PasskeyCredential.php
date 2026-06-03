<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Passkey;

final readonly class PasskeyCredential
{
    /**
     * @param list<string> $transports
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public string $id,
        public string $accountId,
        public string $credentialId,
        public string $publicKey,
        public int $signCount,
        public array $transports,
        public int $createdAt,
        public ?int $lastUsedAt = null,
        public array $metadata = [],
    ) {
    }
}
