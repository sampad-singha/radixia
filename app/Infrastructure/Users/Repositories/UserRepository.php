<?php

namespace App\Infrastructure\Users\Repositories;

use App\Domain\Users\Repositories\UserRepositoryInterface;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class UserRepository implements UserRepositoryInterface
{
    public function findByEmail(string $email): ?User
    {
        return User::query()
            ->where('email', $email)
            ->first();
    }

    public function create(array $data): User
    {
        return User::query()->create($data);
    }

    public function findById(int $id): ?User
    {
        return User::find($id);
    }

    public function save(User $user): void
    {
        $user->save();
    }

    public function markEmailVerified(User $user): void
    {
        if (! $user->hasVerifiedEmail()) {
            $user->markEmailAsVerified();
        }
    }

    public function setPendingEmail(User $user, string $email, string $token): void
    {
        $user->forceFill([
            'pending_email' => $email,
            'pending_email_token' => $token,
        ])->save();
    }

    public function setEmail(User $user, string $email): void
    {
        $user->forceFill([
            'email' => $email,
            'email_verified_at' => now(),
        ])->save();
    }

    public function clearPendingEmail(User $user): void
    {
        $user->forceFill([
            'pending_email' => null,
            'pending_email_token' => null,
        ])->save();
    }

}
