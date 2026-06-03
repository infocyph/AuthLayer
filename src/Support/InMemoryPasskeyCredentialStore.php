<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Passkey\PasskeyCredential;
use Infocyph\AuthLayer\Passkey\PasskeyCredentialStoreInterface;

final class InMemoryPasskeyCredentialStore implements PasskeyCredentialStoreInterface
{
    /**
     * @var array<string, PasskeyCredential>
     */
    private array $credentials = [];

    public function save(PasskeyCredential $credential): void
    {
        $this->credentials[$credential->id] = $credential;
    }

    public function findByCredentialId(string $credentialId): ?PasskeyCredential
    {
        foreach ($this->credentials as $credential) {
            if ($credential->credentialId === $credentialId) {
                return $credential;
            }
        }

        return null;
    }

    public function findForAccount(string $accountId): array
    {
        return array_values(array_filter(
            $this->credentials,
            static fn (PasskeyCredential $credential): bool => $credential->accountId === $accountId,
        ));
    }

    public function updateSignCount(string $credentialId, int $signCount): void
    {
        foreach ($this->credentials as $id => $credential) {
            if ($credential->credentialId !== $credentialId) {
                continue;
            }

            $this->credentials[$id] = new PasskeyCredential(
                id: $credential->id,
                accountId: $credential->accountId,
                credentialId: $credential->credentialId,
                publicKey: $credential->publicKey,
                signCount: $signCount,
                transports: $credential->transports,
                createdAt: $credential->createdAt,
                lastUsedAt: $credential->lastUsedAt,
                metadata: $credential->metadata,
            );
        }
    }

    public function revoke(string $credentialId): void
    {
        foreach ($this->credentials as $id => $credential) {
            if ($credential->credentialId === $credentialId || $credential->id === $credentialId) {
                unset($this->credentials[$id]);
            }
        }
    }
}
