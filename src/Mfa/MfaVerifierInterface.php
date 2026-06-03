<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Mfa;

interface MfaVerifierInterface
{
    public function verify(MfaChallenge $challenge, string $code): MfaVerificationResult;
}
