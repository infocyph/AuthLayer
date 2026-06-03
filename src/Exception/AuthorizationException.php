<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Exception;

class AuthorizationException extends AuthLayerException
{
    public function __construct(
        string $message = 'Authorization failed.',
        private readonly string $reasonCode = 'authorization_denied',
        int $code = 0,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, $code, $previous);
    }

    public function reasonCode(): string
    {
        return $this->reasonCode;
    }
}
