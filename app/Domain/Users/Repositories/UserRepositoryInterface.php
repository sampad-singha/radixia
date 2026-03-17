<?php

namespace App\Domain\Users\Repositories;

use App\Models\User;
use DateTimeInterface;

interface UserRepositoryInterface
{
    public function findByEmail(string $email): ?User;
    public function create(array $data): User;
    public function findById(string $id): ?User;
    public function save(User $user): void;
    public function markEmailVerified(User $user): void;

    // Add these methods
    public function setPendingEmail(User $user, string $email, string $token, DateTimeInterface $expiresAt): void;
    public function setEmail(User $user, string $email): void;
    public function clearPendingEmail(User $user): void;
    public function updatePassword(User $user, string $newPassword): void;
    public function getInstructorStats(string $userId): array;

}
