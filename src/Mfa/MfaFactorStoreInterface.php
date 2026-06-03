<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Mfa;

interface MfaFactorStoreInterface
{
    public function save(MfaFactor $factor): void;

    /**
     * @return list<MfaFactor>
     */
    public function findForAccount(string $accountId): array;

    public function remove(string $factorId): void;
}
