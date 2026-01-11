<?php

namespace App\Domain\Auth\Services;

use App\Models\User;

interface AuthServiceInterface
{
    public function register(array $data, ?string $ip, ?string $userAgent): array;
    public function login(array $data,  ?string $ip, ?string $userAgent): array;
    public function logout(User $user): void;
    public function forgotPassword(array $data, string $client): string;
    public function resetPassword(array $data): string;
    public function verifyEmail(string $id, string $hash): bool;
    public function resendVerificationNotification(User $user): void;
    public function confirmSudoMode(User $user, string $type, string $value): void;
    public function getSudoStatus(User $user): array;
    public function listSessions(User $user): array;
    public function revokeSession(User $user, string $tokenId): void;
    public function revokeOtherSessions(User $user): void;
    public function changePassword(User $user, string $currentPassword, string $newPassword): void;
}
