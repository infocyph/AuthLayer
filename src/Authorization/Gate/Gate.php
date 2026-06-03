<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authorization\Gate;

use Infocyph\AuthLayer\Authorization\Decision\AuthorizationDecision;
use Infocyph\AuthLayer\Authorization\Policy\PolicyInterface;
use Infocyph\AuthLayer\Authorization\Policy\PolicyResolverInterface;
use Infocyph\AuthLayer\Exception\AuthorizationException;
use Infocyph\AuthLayer\Principal\PrincipalInterface;

final class Gate implements AuthorizerInterface
{
    /** @var array<string, callable> */
    private array $abilities = [];

    /** @var list<callable> */
    private array $beforeCallbacks = [];

    /** @var list<callable> */
    private array $afterCallbacks = [];

    public function __construct(
        private readonly ?PolicyResolverInterface $policyResolver = null,
    ) {
    }

    public function define(string $ability, callable $callback): self
    {
        $this->abilities[$ability] = $callback;

        return $this;
    }

    public function before(callable $callback): self
    {
        $this->beforeCallbacks[] = $callback;

        return $this;
    }

    public function after(callable $callback): self
    {
        $this->afterCallbacks[] = $callback;

        return $this;
    }

    public function can(
        PrincipalInterface $principal,
        string $ability,
        mixed $resource = null,
        array $context = [],
    ): AuthorizationDecision {
        foreach ($this->beforeCallbacks as $callback) {
            $result = $callback($principal, $ability, $resource, $context);

            if ($result !== null) {
                return $this->runAfterCallbacks(
                    $principal,
                    $ability,
                    $resource,
                    $context,
                    $this->normalizeDecision($result),
                );
            }
        }

        $decision = $this->resolveDecision($principal, $ability, $resource, $context);

        return $this->runAfterCallbacks($principal, $ability, $resource, $context, $decision);
    }

    public function authorize(
        PrincipalInterface $principal,
        string $ability,
        mixed $resource = null,
        array $context = [],
    ): void {
        $decision = $this->can($principal, $ability, $resource, $context);

        if (! $decision->allowed) {
            throw new AuthorizationException(
                $decision->reason ?? 'Authorization failed.',
                $decision->code,
            );
        }
    }

    private function resolveDecision(
        PrincipalInterface $principal,
        string $ability,
        mixed $resource,
        array $context,
    ): AuthorizationDecision {
        if (array_key_exists($ability, $this->abilities)) {
            return $this->normalizeDecision(
                ($this->abilities[$ability])($principal, $resource, $context),
            );
        }

        $policy = $this->resolvePolicy($resource);

        if ($policy !== null) {
            return $this->normalizeDecision(
                $policy->authorize($principal, $ability, $resource, $context),
            );
        }

        return AuthorizationDecision::deny(
            code: 'ability_not_defined',
            reason: sprintf('No gate or policy resolved for ability "%s".', $ability),
        );
    }

    private function resolvePolicy(mixed $resource): ?PolicyInterface
    {
        if ($resource === null || $this->policyResolver === null) {
            return null;
        }

        return $this->policyResolver->resolve($resource);
    }

    private function runAfterCallbacks(
        PrincipalInterface $principal,
        string $ability,
        mixed $resource,
        array $context,
        AuthorizationDecision $decision,
    ): AuthorizationDecision {
        foreach ($this->afterCallbacks as $callback) {
            $result = $callback($principal, $ability, $resource, $decision, $context);

            if ($result !== null) {
                $decision = $this->normalizeDecision($result);
            }
        }

        return $decision;
    }

    private function normalizeDecision(AuthorizationDecision|bool|null $decision): AuthorizationDecision
    {
        return match (true) {
            $decision instanceof AuthorizationDecision => $decision,
            $decision === true => AuthorizationDecision::allow(),
            default => AuthorizationDecision::deny(),
        };
    }
}
