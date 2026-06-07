<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Gate;

use Infocyph\AuthLayer\Audit\AuthEventSeverity;
use Infocyph\AuthLayer\Audit\AuthEventType;
use Infocyph\AuthLayer\Authorization\Decision\AuthorizationDecision;
use Infocyph\AuthLayer\Contract\Clock\ClockInterface;
use Infocyph\AuthLayer\Contract\Id\AuthIdGeneratorInterface;
use Infocyph\AuthLayer\Contract\Storage\AuditEventStoreInterface;
use Infocyph\AuthLayer\Exception\AuthorizationException;
use Infocyph\AuthLayer\Principal\PrincipalInterface;
use Infocyph\AuthLayer\Support\AuthEventRecorder;
use Infocyph\AuthLayer\Support\ContextValue;
use Infocyph\AuthLayer\Support\SystemClock;

final readonly class AuditingAuthorizer implements AuthorizerInterface
{
    public function __construct(
        private AuthorizerInterface $inner,
        private AuditEventStoreInterface $audit,
        private AuthIdGeneratorInterface $ids,
        private ClockInterface $clock = new SystemClock(),
    ) {}

    public function authorize(PrincipalInterface $principal, string $ability, mixed $resource = null, array $context = []): void
    {
        $decision = $this->can($principal, $ability, $resource, $context);

        if (!$decision->allowed) {
            throw new AuthorizationException(
                $decision->reason ?? 'Authorization failed.',
                $decision->code,
            );
        }
    }

    public function can(PrincipalInterface $principal, string $ability, mixed $resource = null, array $context = []): AuthorizationDecision
    {
        $decision = $this->inner->can($principal, $ability, $resource, $context);

        if (!$decision->allowed) {
            AuthEventRecorder::record(
                $this->audit,
                $this->ids,
                $this->clock,
                AuthEventType::AUTHORIZATION_DENIED,
                $principal->accountId(),
                actorId: $principal->id(),
                metadata: ['ability' => $ability, 'code' => $decision->code, 'reason' => $decision->reason] + $context,
                severity: AuthEventSeverity::WARNING,
                sessionId: ContextValue::stringOrNull($context, 'session_id'),
                deviceId: ContextValue::stringOrNull($context, 'device_id'),
            );
        }

        return $decision;
    }
}
