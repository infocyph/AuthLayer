<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Contract\Storage;

use Infocyph\AuthLayer\Authentication\Session\AuthSession;

interface SessionStoreInterface
{
    public function create(AuthSession $session): void;

    public function find(string $sessionId): ?AuthSession;

    public function rotate(string $sessionId, AuthSession $replacement): void;

    public function touch(string $sessionId, int $lastSeenAt): void;

    public function revoke(string $sessionId): void;

    public function revokeAllForAccount(string $accountId, ?string $exceptSessionId = null): void;
}
