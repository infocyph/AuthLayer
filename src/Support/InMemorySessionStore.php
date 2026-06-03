<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Authentication\Session\AuthSession;
use Infocyph\AuthLayer\Contract\Storage\SessionStoreInterface;

final class InMemorySessionStore implements SessionStoreInterface
{
    /**
     * @var array<string, AuthSession>
     */
    private array $sessions = [];

    public function create(AuthSession $session): void
    {
        $this->sessions[$session->id] = $session;
    }

    public function find(string $sessionId): ?AuthSession
    {
        return $this->sessions[$sessionId] ?? null;
    }

    public function rotate(string $sessionId, AuthSession $replacement): void
    {
        unset($this->sessions[$sessionId]);
        $this->sessions[$replacement->id] = $replacement;
    }

    public function touch(string $sessionId, int $lastSeenAt): void
    {
        $session = $this->sessions[$sessionId] ?? null;

        if ($session === null) {
            return;
        }

        $this->sessions[$sessionId] = $session->seenAt($lastSeenAt);
    }

    public function revoke(string $sessionId): void
    {
        unset($this->sessions[$sessionId]);
    }

    public function revokeAllForAccount(string $accountId, ?string $exceptSessionId = null): void
    {
        foreach ($this->sessions as $sessionId => $session) {
            if ($session->accountId !== $accountId) {
                continue;
            }

            if ($exceptSessionId !== null && $sessionId === $exceptSessionId) {
                continue;
            }

            unset($this->sessions[$sessionId]);
        }
    }
}
