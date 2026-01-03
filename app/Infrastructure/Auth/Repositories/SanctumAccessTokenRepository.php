<?php

namespace App\Infrastructure\Auth\Repositories;

use App\Domain\Auth\Repositories\AccessTokenRepositoryInterface;
use App\Models\User;
use Laravel\Sanctum\PersonalAccessToken;

class SanctumAccessTokenRepository implements AccessTokenRepositoryInterface
{
    public function create(User $user, string $deviceName, ?string $ip, ?string $userAgent): string
    {
        $tokenResult = $user->createToken($deviceName);

        $tokenResult->accessToken->forceFill([
            'ip_address' => $ip,
            'user_agent' => $userAgent,
        ])->save();

        return $tokenResult->plainTextToken;
    }

    public function current(User $user): ?PersonalAccessToken
    {
        $token = $user->currentAccessToken();

        return $token instanceof PersonalAccessToken ? $token : null;
    }

    public function list(User $user): array
    {
        return $user->tokens()
            ->select(['id', 'name', 'ip_address', 'user_agent', 'last_used_at', 'created_at'])
            ->orderByDesc('last_used_at')
            ->get()
            ->toArray();
    }

    public function revoke(User $user, string $tokenId): void
    {
        $user->tokens()->where('id', $tokenId)->delete();
    }


    public function revokeOthers(User $user, int $currentTokenId): void
    {
        $user->tokens()->where('id', '!=', $currentTokenId)->delete();
    }

    public function setSudoExpiration(PersonalAccessToken $token, int $seconds): void
    {
        $token->forceFill([
            'sudo_expires_at' => now()->addSeconds($seconds),
        ])->save();
    }

    public function isSudoActive(User $user): bool
    {
        $token = $this->current($user);

        return $token
            && $token->sudo_expires_at
            && $token->sudo_expires_at->isFuture();
    }

}