<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Grant;

interface GrantStoreInterface
{
    /**
     * @return list<AccessGrant>
     */
    public function grantsForPrincipal(string $principalId): array;

    public function save(AccessGrant $grant): void;

    public function revoke(string $grantId): void;
}
