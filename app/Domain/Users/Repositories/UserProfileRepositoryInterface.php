<?php

namespace App\Domain\Users\Repositories;

use App\Domain\Users\Entities\UserProfile;
use App\Models\User;

interface UserProfileRepositoryInterface
{
    public function findByUser(User $user): UserProfile;
    public function updateOrCreate(User $user, array $data): UserProfile;
}
