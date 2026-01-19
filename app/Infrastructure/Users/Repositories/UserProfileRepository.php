<?php

namespace App\Infrastructure\Users\Repositories;

use App\Domain\Users\Entities\UserProfile;
use App\Domain\Users\Repositories\UserProfileRepositoryInterface;
use App\Models\User;

class UserProfileRepository implements UserProfileRepositoryInterface
{
    public function findByUser(User $user): UserProfile
    {
        return UserProfile::where('user_id', $user->id)->firstOrFail();
    }


    public function updateOrCreate(User $user, array $data): UserProfile
    {
        return UserProfile::updateOrCreate(
            ['user_id' => $user->id],
            $data
        );
    }
}
