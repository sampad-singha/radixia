<?php

namespace App\Infrastructure\Users\Repositories;

use App\Domain\Users\Repositories\UserRepositoryInterface;
use App\Models\User;

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
}
