<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Grant;

use Infocyph\AuthLayer\Authorization\Gate\Ability;
use Infocyph\AuthLayer\Authorization\Gate\AbilityMatcher;
use Infocyph\AuthLayer\Contract\Clock\ClockInterface;
use Infocyph\AuthLayer\Support\SystemClock;

final readonly class GrantResolver
{
    public function __construct(
        private GrantStoreInterface $grants,
        private AbilityMatcher $matcher = new AbilityMatcher(),
        private ClockInterface $clock = new SystemClock(),
    ) {
    }

    /**
     * @return list<AccessGrant>
     */
    public function forPrincipal(string $principalId, Ability $ability): array
    {
        $now = $this->clock->now();
        $matches = [];

        foreach ($this->grants->grantsForPrincipal($principalId) as $grant) {
            if ($grant->isExpiredAt($now)) {
                continue;
            }

            if (! $this->matcher->matches($grant->permission, $ability->name)) {
                continue;
            }

            if ($grant->resourceType !== null && $ability->resourceType === null) {
                continue;
            }

            if ($grant->resourceType !== null && $grant->resourceType !== $ability->resourceType) {
                continue;
            }

            if ($grant->resourceId !== null && $ability->resourceId === null) {
                continue;
            }

            if ($grant->resourceId !== null && $grant->resourceId !== $ability->resourceId) {
                continue;
            }

            $matches[] = $grant;
        }

        return $matches;
    }
}
