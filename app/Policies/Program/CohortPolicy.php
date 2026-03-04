<?php

namespace App\Policies\Program;

use App\Domain\Programs\Entities\Cohort;
use App\Models\User;

class CohortPolicy
{
    /**
     * Create a new policy instance.
     */
    public function __construct()
    {
        //
    }

    public function before(User $user, string $ability): bool|null
    {
        if ($user->isAdmin()) {
            return true;
        }

        return null;
    }

    public function create(User $user): bool
    {
        return $user->can('cohort.create');
    }

    public function update(User $user, Cohort $cohort): bool
    {
        return $cohort->assigned_instructor_id === $user->id;
    }

    public function delete(User $user, Cohort $cohort): bool
    {
        return $this->update($user, $cohort);
    }

    public function restore(User $user, Cohort $cohort): bool
    {
        return $this->update($user, $cohort);
    }

    public function viewAttendance(User $user, Cohort $cohort): bool
    {
        if ($user->id === $cohort->assigned_instructor_id) {
            return true;
        }

        return $cohort->enrollments()
            ->where('user_id', $user->id)
            ->where('status', 'active')
            ->exists();
    }

    public function viewStudentAttendance(User $user, Cohort $cohort, User $student): bool
    {
        if ($user->id === $cohort->assigned_instructor_id) {
            return true;
        }

        return $user->id === $student->id &&
            $cohort->enrollments()
                ->where('user_id', $user->id)
                ->where('status', 'active')
                ->exists();
    }
}
