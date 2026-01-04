<?php

namespace App\Domain\Auth\Repositories;

use App\Models\User;
use Laravel\Sanctum\Contracts\HasAbilities;
use Laravel\Sanctum\PersonalAccessToken;

interface AccessTokenRepositoryInterface
{
    public function create(User $user, string $deviceName, ?string $ip, ?string $userAgent): string;

    public function current(User $user): ?PersonalAccessToken;

    public function list(User $user): array;

    public function revoke(User $user, string $tokenId): void;

    public function revokeOthers(User $user, int $currentTokenId): void;

    public function revokeAll(User $user): void;

    public function setSudoExpiration(PersonalAccessToken $token, int $seconds): void;

    public function isSudoActive(User $user): bool;
}