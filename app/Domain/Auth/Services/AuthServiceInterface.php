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

    /**
     * Verify password and enable Sudo Mode for the current token.
     */
    public function confirmPassword(User $user, string $password): bool;

    /**
     * Check if Sudo Mode is active for the current token.
     */
    public function passwordConfirmedStatus(User $user): bool;
}
