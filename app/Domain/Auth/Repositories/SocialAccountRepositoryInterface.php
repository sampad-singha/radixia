<?php

namespace App\Domain\Auth\Repositories;

use App\Models\SocialAccount;
use App\Models\User;

interface SocialAccountRepositoryInterface
{
    public function findByProvider(string $provider, string $providerId): ?SocialAccount;

    public function create(
        User $user,
        string $provider,
        string $providerId,
        string $token,
        ?string $refreshToken,
        ?int $expiresIn,
        ?string $avatar
    ): SocialAccount;

    public function updateTokens(
        SocialAccount $account,
        string $token,
        ?string $refreshToken,
        ?int $expiresIn
    ): SocialAccount;

    public function registerUserWithSocial(array $userData, string $provider, object $providerUser): User;
}