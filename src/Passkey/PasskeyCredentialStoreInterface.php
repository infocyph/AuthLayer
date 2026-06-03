<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Passkey;

interface PasskeyCredentialStoreInterface
{
    public function save(PasskeyCredential $credential): void;

    public function findByCredentialId(string $credentialId): ?PasskeyCredential;

    /**
     * @return list<PasskeyCredential>
     */
    public function findForAccount(string $accountId): array;

    public function updateSignCount(string $credentialId, int $signCount): void;

    public function revoke(string $credentialId): void;
}
