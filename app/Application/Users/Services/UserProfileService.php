<?php

namespace App\Application\Users\Services;

use App\Domain\Users\Entities\UserProfile;
use App\Domain\Users\Repositories\UserProfileRepositoryInterface;
use App\Domain\Users\Services\UserProfileServiceInterface;
use App\Models\User;

readonly class UserProfileService implements UserProfileServiceInterface
{
    public function __construct(
        private UserProfileRepositoryInterface $repository
    ) {}


    public function getProfile(User $user): UserProfile
    {
        return UserProfile::where('user_id', $user->id)->firstOrFail();
    }

    public function updateProfile(User $user, array $data): UserProfile
    {
        // Add any domain logic here (e.g., preventing banned users from updating)

        return $this->repository->updateOrCreate($user, $data);
    }
}