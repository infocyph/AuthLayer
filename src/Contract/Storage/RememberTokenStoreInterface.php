<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Contract\Storage;

use Infocyph\AuthLayer\Authentication\RememberMe\RememberTokenRecord;

interface RememberTokenStoreInterface
{
    public function save(RememberTokenRecord $record): void;

    public function find(string $recordId): ?RememberTokenRecord;

    public function findBySelector(string $selector): ?RememberTokenRecord;

    public function rotate(string $recordId, RememberTokenRecord $replacement): void;

    public function revokeFamily(string $familyId): void;

    public function wasFamilyRevoked(string $familyId): bool;
}
