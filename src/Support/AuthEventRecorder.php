<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Audit\AuthEvent;
use Infocyph\AuthLayer\Audit\AuthEventSeverity;
use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Contract\Clock\ClockInterface;
use Infocyph\AuthLayer\Contract\Id\AuthIdGeneratorInterface;
use Infocyph\AuthLayer\Contract\Storage\AuditEventStoreInterface;

final class AuthEventRecorder
{
    /**
     * @param array<string, mixed> $metadata
     */
    public static function record(
        AuditEventStoreInterface $audit,
        AuthIdGeneratorInterface $ids,
        ClockInterface $clock,
        AuthEventType $type,
        ?string $accountId,
        ?string $actorId = null,
        array $metadata = [],
        AuthEventSeverity $severity = AuthEventSeverity::INFO,
        ?string $deviceId = null,
        ?string $sessionId = null,
    ): void {
        $audit->record(new AuthEvent(
            id: $ids->auditEventId(),
            type: $type,
            severity: $severity,
            accountId: $accountId,
            actorId: $actorId ?? $accountId,
            sessionId: $sessionId ?? ContextValue::stringOrNull($metadata, 'session_id'),
            deviceId: $deviceId ?? ContextValue::stringOrNull($metadata, 'device_id'),
            correlationId: $ids->correlationId(),
            occurredAt: $clock->now(),
            metadata: $metadata,
        ));
    }
}
