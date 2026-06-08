<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Contract\Storage;

use Infocyph\AuthLayer\Account\AccountInterface;
use Infocyph\AuthLayer\Account\AccountStatus;

interface AccountStoreInterface
{
    public function markVerified(string $accountId, int $verifiedAt): void;

    public function save(AccountInterface $account): void;

    /**
     * @param array<string, mixed> $metadata
     */
    public function updateMetadata(string $accountId, array $metadata): void;

    public function updatePasswordHash(string $accountId, string $passwordHash): void;

    public function updateStatus(string $accountId, AccountStatus $status): void;
}
