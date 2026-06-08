<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Grant;

interface GrantStoreInterface
{
    /**
     * @return list<AccessGrant>
     */
    public function grantsForPrincipal(string $principalId): array;

    public function revoke(string $grantId): void;

    public function save(AccessGrant $grant): void;
}
