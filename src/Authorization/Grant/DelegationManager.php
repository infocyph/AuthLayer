<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Grant;

use Infocyph\AuthLayer\Audit\AuthEvent;
use Infocyph\AuthLayer\Audit\AuthEventSeverity;
use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Contract\Clock\ClockInterface;
use Infocyph\AuthLayer\Contract\Id\AuthIdGeneratorInterface;
use Infocyph\AuthLayer\Contract\Storage\AuditEventStoreInterface;
use Infocyph\AuthLayer\Support\SystemClock;

final readonly class DelegationManager
{
    public function __construct(
        private GrantStoreInterface $grants,
        private AuditEventStoreInterface $audit,
        private AuthIdGeneratorInterface $ids,
        private ClockInterface $clock = new SystemClock(),
    ) {
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public function grant(string $principalId, string $permission, ?string $resourceType = null, ?string $resourceId = null, ?int $expiresAt = null, array $metadata = []): DelegationResult
    {
        $grant = new AccessGrant(
            id: $this->ids->grantId(),
            principalId: $principalId,
            permission: $permission,
            resourceType: $resourceType,
            resourceId: $resourceId,
            expiresAt: $expiresAt,
            metadata: $metadata,
        );

        $this->grants->save($grant);
        $this->recordAudit(AuthEventType::DELEGATED_ACCESS_GRANTED, $principalId, ['grant_id' => $grant->id, 'permission' => $permission] + $metadata);

        return new DelegationResult(DelegationStatus::GRANTED, grant: $grant, code: 'delegated_access_granted', context: $metadata);
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public function revoke(string $grantId, ?string $principalId = null, array $metadata = []): DelegationResult
    {
        $this->grants->revoke($grantId);
        $this->recordAudit(AuthEventType::DELEGATED_ACCESS_REVOKED, $principalId, ['grant_id' => $grantId] + $metadata);

        return new DelegationResult(DelegationStatus::REVOKED, code: 'delegated_access_revoked', context: $metadata);
    }

    public function listForPrincipal(string $principalId): DelegationResult
    {
        return new DelegationResult(DelegationStatus::LISTED, grants: $this->grants->grantsForPrincipal($principalId), code: 'delegated_access_listed');
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private function recordAudit(AuthEventType $type, ?string $principalId, array $metadata): void
    {
        $this->audit->record(new AuthEvent(
            id: $this->ids->auditEventId(),
            type: $type,
            severity: AuthEventSeverity::NOTICE,
            accountId: $principalId,
            actorId: $principalId,
            sessionId: $metadata['session_id'] ?? null,
            deviceId: $metadata['device_id'] ?? null,
            correlationId: $this->ids->correlationId(),
            occurredAt: $this->clock->now(),
            metadata: $metadata,
        ));
    }
}
