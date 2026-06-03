<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Mfa\MfaFactor;
use Infocyph\AuthLayer\Mfa\MfaFactorStoreInterface;

final class InMemoryMfaFactorStore implements MfaFactorStoreInterface
{
    /**
     * @var array<string, MfaFactor>
     */
    private array $factors = [];

    public function save(MfaFactor $factor): void
    {
        $this->factors[$factor->id] = $factor;
    }

    public function findForAccount(string $accountId): array
    {
        return array_values(array_filter(
            $this->factors,
            static fn (MfaFactor $factor): bool => $factor->accountId === $accountId,
        ));
    }

    public function remove(string $factorId): void
    {
        unset($this->factors[$factorId]);
    }
}
