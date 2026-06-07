<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\Support;

use Infocyph\AuthLayer\Audit\AuthEventSeverity;
use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Contract\Clock\ClockInterface;
use Infocyph\AuthLayer\Contract\Id\AuthIdGeneratorInterface;
use Infocyph\AuthLayer\Contract\Notification\AuthNotifierInterface;
use Infocyph\AuthLayer\Contract\Security\TokenVerificationResult;
use Infocyph\AuthLayer\Contract\Storage\AccountStoreInterface;
use Infocyph\AuthLayer\Contract\Storage\AuditEventStoreInterface;
use Infocyph\AuthLayer\Support\AuthEventRecorder;
use Infocyph\AuthLayer\Support\ContextValue;
use Infocyph\AuthLayer\Support\SystemClock;

abstract readonly class AbstractTokenRequestManager
{
    public function __construct(
        protected AccountStoreInterface $accounts,
        protected AuthNotifierInterface $notifier,
        protected AuditEventStoreInterface $audit,
        protected AuthIdGeneratorInterface $ids,
        protected int $ttlSeconds = 3600,
        protected ClockInterface $clock = new SystemClock(),
    ) {}

    /**
     * @param array<string, mixed> $context
     * @param array<string, mixed> $metadata
     */
    protected function recordEvent(
        AuthEventType $type,
        string $accountId,
        array $context = [],
        array $metadata = [],
        AuthEventSeverity $severity = AuthEventSeverity::INFO,
    ): void {
        AuthEventRecorder::record(
            $this->audit,
            $this->ids,
            $this->clock,
            $type,
            $accountId,
            metadata: $metadata + $context,
            severity: $severity,
            sessionId: ContextValue::stringOrNull($context, 'session_id'),
            deviceId: ContextValue::stringOrNull($context, 'device_id'),
        );
    }

    protected function resolveRequestId(TokenVerificationResult $verification): ?string
    {
        $requestId = $verification->claims['request_id'] ?? $verification->tokenId;

        return is_string($requestId) && $requestId !== '' ? $requestId : null;
    }
}
