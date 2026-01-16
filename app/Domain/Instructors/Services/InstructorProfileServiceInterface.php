<?php

namespace App\Domain\Instructors\Services;

use App\Domain\Instructors\Entities\InstructorProfile;
use App\Models\User;

interface InstructorProfileServiceInterface
{
    public function getProfile(User $user): ?InstructorProfile;
    public function createProfile(User $user, array $data): InstructorProfile;
    public function updateProfile(User $user, array $data): InstructorProfile;
}
