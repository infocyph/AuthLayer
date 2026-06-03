<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\Lockout;

use Infocyph\AuthLayer\Audit\AuthEvent;
use Infocyph\AuthLayer\Audit\AuthEventSeverity;
use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Contract\Cache\CounterStoreInterface;
use Infocyph\AuthLayer\Contract\Clock\ClockInterface;
use Infocyph\AuthLayer\Contract\Id\AuthIdGeneratorInterface;
use Infocyph\AuthLayer\Contract\Storage\AuditEventStoreInterface;
use Infocyph\AuthLayer\Contract\Storage\LockoutReason;
use Infocyph\AuthLayer\Contract\Storage\LockoutStoreInterface;
use Infocyph\AuthLayer\Support\SystemClock;

final readonly class LockoutManager
{
    public function __construct(
        private CounterStoreInterface $counters,
        private LockoutStoreInterface $locks,
        private AuditEventStoreInterface $audit,
        private AuthIdGeneratorInterface $ids,
        private LockoutConfig $config = new LockoutConfig(),
        private ClockInterface $clock = new SystemClock(),
    ) {
    }

    public function recordLoginFailure(string $accountId, array $context = []): LockoutResult
    {
        return $this->recordFailure($accountId, 'login', $this->config->maxLoginFailures, LockoutReason::TOO_MANY_LOGIN_ATTEMPTS, $context);
    }

    public function recordMfaFailure(string $accountId, array $context = []): LockoutResult
    {
        return $this->recordFailure($accountId, 'mfa', $this->config->maxMfaFailures, LockoutReason::TOO_MANY_MFA_FAILURES, $context);
    }

    public function recordPasskeyFailure(string $accountId, array $context = []): LockoutResult
    {
        return $this->recordFailure($accountId, 'passkey', $this->config->maxPasskeyFailures, LockoutReason::TOO_MANY_PASSKEY_FAILURES, $context);
    }

    public function clearFailures(string $accountId): void
    {
        $this->counters->reset($this->counterKey('login', $accountId));
        $this->counters->reset($this->counterKey('mfa', $accountId));
        $this->counters->reset($this->counterKey('passkey', $accountId));
    }

    public function isLocked(string $accountId): bool
    {
        return $this->locks->isLocked($accountId);
    }

    public function lock(string $accountId, LockoutReason $reason, ?int $until = null, array $context = []): LockoutResult
    {
        $lockedUntil = $until ?? ($this->clock->now() + $this->config->lockSeconds);
        $this->locks->lock($accountId, $reason, $lockedUntil);
        $this->recordAudit(AuthEventType::LOCKOUT_TRIGGERED, $accountId, ['reason' => $reason->value, 'until' => $lockedUntil] + $context, AuthEventSeverity::WARNING);

        return new LockoutResult(LockoutStatus::LOCKED, $accountId, $reason, $lockedUntil, code: 'account_locked', context: $context);
    }

    public function unlock(string $accountId, array $context = []): LockoutResult
    {
        $this->locks->unlock($accountId);
        $this->clearFailures($accountId);
        $this->recordAudit(AuthEventType::LOCKOUT_CLEARED, $accountId, $context);

        return new LockoutResult(LockoutStatus::UNLOCKED, $accountId, code: 'account_unlocked', context: $context);
    }

    private function recordFailure(string $accountId, string $type, int $threshold, LockoutReason $reason, array $context): LockoutResult
    {
        $attempts = $this->counters->increment($this->counterKey($type, $accountId), ttlSeconds: $this->config->windowSeconds);

        if ($attempts >= $threshold) {
            return $this->lock($accountId, $reason, null, ['attempts' => $attempts] + $context);
        }

        return new LockoutResult(
            LockoutStatus::FAILURE_RECORDED,
            $accountId,
            $reason,
            attempts: $attempts,
            code: $type . '_failure_recorded',
            context: $context,
        );
    }

    private function counterKey(string $type, string $accountId): string
    {
        return 'lockout:' . $type . ':' . $accountId;
    }

    private function recordAudit(AuthEventType $type, string $accountId, array $metadata = [], AuthEventSeverity $severity = AuthEventSeverity::INFO): void
    {
        $this->audit->record(new AuthEvent(
            id: $this->ids->auditEventId(),
            type: $type,
            severity: $severity,
            accountId: $accountId,
            actorId: $accountId,
            sessionId: $metadata['session_id'] ?? null,
            deviceId: $metadata['device_id'] ?? null,
            correlationId: $this->ids->correlationId(),
            occurredAt: $this->clock->now(),
            metadata: $metadata,
        ));
    }
}
