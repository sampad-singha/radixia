<?php

namespace App\Policies\Program;

use App\Domain\Programs\Entities\CohortSession;
use App\Models\User;

class CohortSessionPolicy
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
        return $user->can('cohortSession.create');
    }

    public function update(User $user, CohortSession $session): bool
    {
        return $user->id === $session->cohort->assigned_instructor_id;
    }

    public function delete(User $user, CohortSession $session): bool
    {
        return $this->update($user, $session);
    }

    public function restore(User $user, CohortSession $session): bool
    {
        return $this->update($user, $session);
    }

    public function join(User $user, CohortSession $session): bool
    {
        if ($user->isInstructor()) {
            return $session->cohort->assigned_instructor_id === $user->id;
        }

        return true;
    }

    public function complete(User $user, CohortSession $session): bool
    {
        return $this->update($user, $session);
    }

    public function cancel(User $user, CohortSession $session): bool
    {
        return $this->update($user, $session);
    }
}
