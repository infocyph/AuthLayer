<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Authentication\RememberMe;

use Infocyph\AuthLayer\Support\AbstractCodeContextResult;
use Infocyph\AuthLayer\Support\HasEnumStatusResult;

final readonly class RememberMeResult extends AbstractCodeContextResult
{
    use HasEnumStatusResult;

    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public RememberTokenStatus $status,
        public ?RememberToken $token = null,
        public ?RememberTokenRecord $record = null,
        ?string $code = null,
        array $context = [],
    ) {
        parent::__construct($code, $context);
    }

    public function verified(): bool
    {
        return $this->status === RememberTokenStatus::VERIFIED;
    }

    /**
     * @return list<object>
     */
    protected function successStatuses(): array
    {
        return [
            RememberTokenStatus::ISSUED,
            RememberTokenStatus::ROTATED,
            RememberTokenStatus::VERIFIED,
            RememberTokenStatus::REVOKED,
        ];
    }
}
