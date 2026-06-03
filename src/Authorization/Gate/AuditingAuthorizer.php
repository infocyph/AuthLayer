<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Gate;

use Infocyph\AuthLayer\Audit\AuthEvent;
use Infocyph\AuthLayer\Audit\AuthEventSeverity;
use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Contract\Clock\ClockInterface;
use Infocyph\AuthLayer\Contract\Id\AuthIdGeneratorInterface;
use Infocyph\AuthLayer\Contract\Storage\AuditEventStoreInterface;
use Infocyph\AuthLayer\Principal\PrincipalInterface;
use Infocyph\AuthLayer\Support\SystemClock;

final readonly class AuditingAuthorizer implements AuthorizerInterface
{
    public function __construct(
        private AuthorizerInterface $inner,
        private AuditEventStoreInterface $audit,
        private AuthIdGeneratorInterface $ids,
        private ClockInterface $clock = new SystemClock(),
    ) {
    }

    public function can(PrincipalInterface $principal, string $ability, mixed $resource = null, array $context = []): \Infocyph\AuthLayer\Authorization\Decision\AuthorizationDecision
    {
        $decision = $this->inner->can($principal, $ability, $resource, $context);

        if (! $decision->allowed) {
            $this->audit->record(new AuthEvent(
                id: $this->ids->auditEventId(),
                type: AuthEventType::AUTHORIZATION_DENIED,
                severity: AuthEventSeverity::WARNING,
                accountId: $principal->accountId(),
                actorId: $principal->id(),
                sessionId: $context['session_id'] ?? null,
                deviceId: $context['device_id'] ?? null,
                correlationId: $this->ids->correlationId(),
                occurredAt: $this->clock->now(),
                metadata: ['ability' => $ability, 'code' => $decision->code, 'reason' => $decision->reason] + $context,
            ));
        }

        return $decision;
    }

    public function authorize(PrincipalInterface $principal, string $ability, mixed $resource = null, array $context = []): void
    {
        $this->inner->authorize($principal, $ability, $resource, $context);
    }
}
