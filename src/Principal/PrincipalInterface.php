<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Principal;

interface PrincipalInterface
{
    public function id(): string;

    public function type(): PrincipalType;

    public function accountId(): ?string;

    /**
     * @return array<string, mixed>
     */
    public function metadata(): array;
}
