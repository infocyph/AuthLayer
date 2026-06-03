<?php

declare(strict_types=1);

namespace Infocyph\AuthLayer\Contract\Storage;

use Infocyph\AuthLayer\Authentication\TokenAuth\RefreshTokenRecord;

interface RefreshTokenStoreInterface
{
    public function save(RefreshTokenRecord $record): void;

    public function find(string $tokenId): ?RefreshTokenRecord;

    public function rotate(string $tokenId, RefreshTokenRecord $replacement): void;

    public function revokeFamily(string $familyId): void;

    public function wasFamilyRevoked(string $familyId): bool;
}
