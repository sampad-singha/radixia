<?php

namespace App\Domain\Users\Services;

use App\Domain\Users\Entities\UserProfile;
use App\Models\User;

interface UserProfileServiceInterface
{
    public function getProfile(User $user): ?UserProfile;
    public function updateProfile(User $user, array $data): UserProfile;
}
