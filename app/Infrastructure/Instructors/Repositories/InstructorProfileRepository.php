<?php

namespace App\Infrastructure\Instructors\Repositories;

use App\Domain\Instructors\Entities\InstructorProfile;
use App\Domain\Instructors\Repositories\InstructorProfileRepositoryInterface;
use App\Models\User;

class InstructorProfileRepository implements InstructorProfileRepositoryInterface
{
    public function findByUserId(string $userId): ?InstructorProfile
    {
        return InstructorProfile::where('user_id', $userId)->first();
    }

    public function create(User $user, array $data): InstructorProfile
    {
        return InstructorProfile::create([
            'user_id' => $user->id,
            ...$data,
            'verification_status' => 'pending',
            'is_verified' => false,
        ]);
    }

    public function update(InstructorProfile $profile, array $data): InstructorProfile
    {
        $profile->update($data);
        return $profile->fresh();
    }
}
