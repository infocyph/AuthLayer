<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Support;

use Infocyph\AuthLayer\Contract\Security\TokenVerificationResult;

final class ConsumableTokenRequestProcessor
{
    /**
     * @template TRequest of object
     * @template TResult of object
     * @param callable(TokenVerificationResult): ?TRequest $resolveRequest
     * @param callable(string): TResult $invalidResult
     * @param callable(): TResult $missingRequestResult
     * @param callable(TRequest): bool $isConsumed
     * @param callable(TRequest): TResult $consumedResult
     * @param callable(TRequest): bool $isExpired
     * @param callable(TRequest): TResult $expiredResult
     * @param callable(TRequest): TResult $successResult
     * @return TResult
     */
    public static function process(
        TokenVerificationResult $verification,
        callable $resolveRequest,
        callable $invalidResult,
        callable $missingRequestResult,
        callable $isConsumed,
        callable $consumedResult,
        callable $isExpired,
        callable $expiredResult,
        callable $successResult,
    ): object {
        if (!$verification->verified) {
            return $invalidResult($verification->failureReason ?? 'invalid_token');
        }

        $request = $resolveRequest($verification);

        if ($request === null) {
            return $missingRequestResult();
        }

        if ($isConsumed($request)) {
            return $consumedResult($request);
        }

        if ($isExpired($request)) {
            return $expiredResult($request);
        }

        return $successResult($request);
    }
}
