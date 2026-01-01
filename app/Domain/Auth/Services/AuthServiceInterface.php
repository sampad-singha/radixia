<?php

namespace App\Domain\Auth\Services;

use App\Models\User;

interface AuthServiceInterface
{
    public function register(array $data): array;
    public function login(array $data): array;
    public function logout(User $user): void;
    public function forgotPassword(array $data): string;
    public function resetPassword(array $data): string;
    public function verifyEmail(int $id, string $hash): bool;
    public function resendVerificationNotification(User $user): void;
}
