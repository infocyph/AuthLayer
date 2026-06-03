<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Account\Account;
use Infocyph\AuthLayer\Account\AccountInterface;
use Infocyph\AuthLayer\Account\AccountStatus;
use Infocyph\AuthLayer\Contract\Storage\AccountProviderInterface;
use Infocyph\AuthLayer\Contract\Storage\AccountStoreInterface;
use Infocyph\AuthLayer\Exception\StorageException;

final class InMemoryAccountStore implements AccountProviderInterface, AccountStoreInterface
{
    /**
     * @var array<string, AccountInterface>
     */
    private array $accounts = [];

    public function save(AccountInterface $account): void
    {
        $this->accounts[$account->id()] = $account;
    }

    public function findById(string $id): ?AccountInterface
    {
        return $this->accounts[$id] ?? null;
    }

    public function findByIdentifier(string $identifier): ?AccountInterface
    {
        foreach ($this->accounts as $account) {
            if ($account->identifier() === $identifier) {
                return $account;
            }
        }

        return null;
    }

    public function markVerified(string $accountId, int $verifiedAt): void
    {
        $account = $this->requireConcreteAccount($accountId);
        $metadata = $account->metadata();
        $metadata['verified_at'] = $verifiedAt;

        $updated = $account
            ->withMetadata($metadata)
            ->withStatus($account->status() === AccountStatus::PENDING_VERIFICATION ? AccountStatus::ACTIVE : $account->status());

        $this->accounts[$accountId] = $updated;
    }

    public function updatePasswordHash(string $accountId, string $passwordHash): void
    {
        $account = $this->requireConcreteAccount($accountId);
        $this->accounts[$accountId] = $account->withPasswordHash($passwordHash);
    }

    public function updateStatus(string $accountId, AccountStatus $status): void
    {
        $account = $this->requireConcreteAccount($accountId);
        $this->accounts[$accountId] = $account->withStatus($status);
    }

    public function updateMetadata(string $accountId, array $metadata): void
    {
        $account = $this->requireConcreteAccount($accountId);
        $this->accounts[$accountId] = $account->withMetadata($metadata);
    }

    private function requireConcreteAccount(string $accountId): Account
    {
        $account = $this->requireAccount($accountId);

        if (! $account instanceof Account) {
            throw new StorageException(sprintf('Account "%s" must be an %s instance for in-memory mutation.', $accountId, Account::class));
        }

        return $account;
    }

    private function requireAccount(string $accountId): AccountInterface
    {
        $account = $this->accounts[$accountId] ?? null;

        if ($account === null) {
            throw new StorageException(sprintf('Account "%s" was not found.', $accountId));
        }

        return $account;
    }
}
