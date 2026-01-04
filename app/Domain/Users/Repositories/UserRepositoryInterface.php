<?php

namespace App\Domain\Users\Repositories;

use App\Models\User;

interface UserRepositoryInterface
{
    public function findByEmail(string $email): ?User;
    public function create(array $data): User;
    public function findById(int $id): ?User;
    public function save(User $user): void;
    public function markEmailVerified(User $user): void;

    // Add these methods
    public function setPendingEmail(User $user, string $email, string $token): void;
    public function setEmail(User $user, string $email): void;
    public function clearPendingEmail(User $user): void;

}
