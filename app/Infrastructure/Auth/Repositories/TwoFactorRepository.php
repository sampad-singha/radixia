<?php

namespace App\Infrastructure\Auth\Repositories;

use App\Domain\Auth\Repositories\TwoFactorRepositoryInterface;
use App\Models\User;

class TwoFactorRepository implements TwoFactorRepositoryInterface
{
    public function enable(User $user, string $secret, array $recoveryCodes): void
    {
        $user->forceFill([
            'two_factor_secret' => encrypt($secret),
            'two_factor_recovery_codes' => encrypt(json_encode($recoveryCodes)),
        ])->save();
    }

    public function confirm(User $user): void
    {
        $user->forceFill([
            'two_factor_confirmed_at' => now(),
        ])->save();
    }

    public function disable(User $user): void
    {
        $user->forceFill([
            'two_factor_secret' => null,
            'two_factor_recovery_codes' => null,
            'two_factor_confirmed_at' => null,
        ])->save();
    }

    public function regenerateRecoveryCodes(User $user, array $codes): array
    {
        $user->forceFill([
            'two_factor_recovery_codes' => encrypt(json_encode($codes)),
        ])->save();

        return $codes;
    }

    public function getRecoveryCodes(User $user): array
    {
        if (! $user->two_factor_recovery_codes) {
            return [];
        }

        return json_decode(decrypt($user->two_factor_recovery_codes), true);
    }

    public function getSecret(User $user): ?string
    {
        if (! $user->two_factor_secret) {
            return null;
        }

        return decrypt($user->two_factor_secret);
    }
}