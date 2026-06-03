<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Passkey;

interface PasskeyServiceInterface
{
    public function startRegistration(string $accountId): PasskeyChallenge;

    public function finishRegistration(PasskeyRegistrationResult $result): PasskeyCredential;

    public function startAuthentication(?string $accountId = null): PasskeyChallenge;

    public function finishAuthentication(PasskeyAuthenticationResult $result): PasskeyVerificationResult;
}
