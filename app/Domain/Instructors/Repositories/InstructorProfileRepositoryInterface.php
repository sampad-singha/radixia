<?php

namespace App\Domain\Instructors\Repositories;

use App\Domain\Instructors\Entities\InstructorProfile;
use App\Models\User;

interface InstructorProfileRepositoryInterface
{
    public function findByUserId(string $userId): ?InstructorProfile;
    public function create(User $user, array $data): InstructorProfile;
    public function update(InstructorProfile $profile, array $data): InstructorProfile;
}
