<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\Session;

use Infocyph\AuthLayer\Contract\Clock\ClockInterface;
use Infocyph\AuthLayer\Contract\Id\AuthIdGeneratorInterface;
use Infocyph\AuthLayer\Contract\Storage\SessionStoreInterface;
use Infocyph\AuthLayer\Exception\SessionException;
use Infocyph\AuthLayer\Support\SystemClock;

final readonly class SessionManager
{
    public function __construct(
        private SessionStoreInterface $sessions,
        private AuthIdGeneratorInterface $ids,
        private SessionConfig $config = new SessionConfig(),
        private ClockInterface $clock = new SystemClock(),
    ) {
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public function create(string $accountId, ?string $deviceId = null, array $metadata = []): AuthSession
    {
        $now = $this->clock->now();
        $session = new AuthSession(
            id: $this->ids->sessionId(),
            accountId: $accountId,
            deviceId: $deviceId,
            createdAt: $now,
            lastSeenAt: $now,
            expiresAt: $now + $this->config->absoluteTtlSeconds,
            recentAuthAt: $now,
            metadata: $metadata,
        );

        $this->sessions->create($session);

        return $session;
    }

    public function rotate(string $sessionId): AuthSession
    {
        $existing = $this->sessions->find($sessionId);

        if ($existing === null) {
            throw new SessionException(sprintf('Session "%s" was not found.', $sessionId));
        }

        $now = $this->clock->now();
        $replacement = new AuthSession(
            id: $this->ids->sessionId(),
            accountId: $existing->accountId,
            deviceId: $existing->deviceId,
            createdAt: $now,
            lastSeenAt: $now,
            expiresAt: $now + $this->config->absoluteTtlSeconds,
            recentAuthAt: $existing->recentAuthAt,
            metadata: $existing->metadata,
        );

        $this->sessions->rotate($sessionId, $replacement);

        return $replacement;
    }

    public function touch(string $sessionId): ?AuthSession
    {
        $session = $this->sessions->find($sessionId);

        if ($session === null) {
            return null;
        }

        $now = $this->clock->now();
        $this->sessions->touch($sessionId, $now);

        return $session->seenAt($now);
    }

    public function revoke(string $sessionId): void
    {
        $this->sessions->revoke($sessionId);
    }

    public function revokeAllForAccount(string $accountId, ?string $exceptSessionId = null): void
    {
        $this->sessions->revokeAllForAccount($accountId, $exceptSessionId);
    }

    public function isExpired(AuthSession $session): bool
    {
        return $session->isExpiredAt($this->clock->now());
    }

    public function isRecentlyAuthenticated(AuthSession $session, int $windowSeconds): bool
    {
        return $session->recentAuthAt !== null && $session->recentAuthAt >= ($this->clock->now() - $windowSeconds);
    }

    public function status(AuthSession $session): SessionStatus
    {
        return $this->isExpired($session) ? SessionStatus::EXPIRED : SessionStatus::ACTIVE;
    }
}
