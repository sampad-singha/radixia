<?php

namespace App\Domain\Auth\Repositories;

use App\Models\User;

interface TwoFactorRepositoryInterface
{
    public function enable(User $user, string $secret, array $recoveryCodes): void;

    public function confirm(User $user): void;

    public function disable(User $user): void;

    public function regenerateRecoveryCodes(User $user, array $codes): array;

    public function getRecoveryCodes(User $user): array;

    public function getSecret(User $user): ?string;
}