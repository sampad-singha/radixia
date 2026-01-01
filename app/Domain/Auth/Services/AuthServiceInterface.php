<?php

namespace App\Domain\Auth\Services;

use App\Models\User;

interface AuthServiceInterface
{
    public function register(array $data): array; // ['user' => User, 'token' => string]
    public function login(array $data): array;    // ['user' => User, 'token' => string]
    public function logout(User $user): void;
    public function forgotPassword(array $data): string;
    public function resetPassword(array $data): string;
}
