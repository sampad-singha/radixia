<?php

namespace App\Infrastructure\Auth\Repositories;

use App\Domain\Auth\Entities\SocialAccount;
use App\Domain\Auth\Repositories\SocialAccountRepositoryInterface;
use App\Domain\Users\Entities\UserProfile;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Throwable;

class SocialAccountRepository implements SocialAccountRepositoryInterface
{
    public function findByProvider(string $provider, string $providerId): ?SocialAccount
    {
        return SocialAccount::where('provider_name', $provider)
            ->where('provider_id', $providerId)
            ->first();
    }

    public function create(
        User $user,
        string                $provider,
        string                $providerId,
        string                $token,
        ?string               $refreshToken,
        ?int                  $expiresIn,
        ?string               $avatar
    ): SocialAccount {
        return $user->socialAccounts()->create([
            'provider_name' => $provider,
            'provider_id' => $providerId,
            'token' => $token,
            'refresh_token' => $refreshToken,
            'expires_in' => $expiresIn,
            'avatar' => $avatar,
        ]);
    }

    public function updateTokens(
        SocialAccount $account,
        string $token,
        ?string $refreshToken,
        ?int $expiresIn
    ): SocialAccount {
        $data = ['token' => $token, 'expires_in' => $expiresIn];

        // Only update refresh token if a new one is provided (Providers don't always send it)
        if ($refreshToken) {
            $data['refresh_token'] = $refreshToken;
        }

        $account->update($data);
        return $account;
    }

    /**
     * @throws Throwable
     */
    public function registerUserWithSocial(array $userData, string $provider, object $providerUser): User
    {
        return DB::transaction(function () use ($userData, $provider, $providerUser) {

            // 1. Create User (Standard Eloquent)
            // We use forceFill/save or standard create depending on if email_verified_at is guarded
            $user = new User();
            $user->forceFill($userData);
            $user->save();

            // 2. Link Account
            $this->create(
                $user,
                $provider,
                $providerUser->getId(),
                $providerUser->token,
                $providerUser->refreshToken,
                $providerUser->expiresIn,
                $providerUser->getAvatar()
            );

            // 3. Create User Profile with sensible defaults
            UserProfile::create([
                'user_id' => $user->id,
                'avatar_url' => $providerUser->getAvatar(),
                'locale' => isset($providerUser->user['locale'])
                    ? substr($providerUser->user['locale'], 0, 2)
                    : 'en',
                'marketing_opt_in' => false,
                'timezone' => null,
            ]);

            return $user;
        });
    }
}
