<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Account;

interface AccountInterface
{
    public function id(): string;

    public function identifier(): string;

    public function status(): AccountStatus;

    public function passwordHash(): ?string;

    /**
     * @return array<string, mixed>
     */
    public function metadata(): array;
}
