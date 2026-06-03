<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Authorization\Grant\AccessGrant;
use Infocyph\AuthLayer\Authorization\Grant\GrantStoreInterface;

final class InMemoryGrantStore implements GrantStoreInterface
{
    /**
     * @var array<string, AccessGrant>
     */
    private array $grants = [];

    public function grantsForPrincipal(string $principalId): array
    {
        return array_values(array_filter(
            $this->grants,
            static fn (AccessGrant $grant): bool => $grant->principalId === $principalId,
        ));
    }

    public function save(AccessGrant $grant): void
    {
        $this->grants[$grant->id] = $grant;
    }

    public function revoke(string $grantId): void
    {
        unset($this->grants[$grantId]);
    }
}
