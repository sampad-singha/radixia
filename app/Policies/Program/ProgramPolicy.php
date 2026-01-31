<?php

namespace App\Policies\Program;

use App\Domain\Programs\Entities\Program;
use App\Models\User;
use Illuminate\Auth\Access\HandlesAuthorization;

class ProgramPolicy
{
    use HandlesAuthorization;
    /**
     * Create a new policy instance.
     */
    public function __construct()
    {
        //
    }

    public function before(User $user, string $ability): ?bool
    {
        if ($user->hasRole(['super-admin', 'admin'])) {
            return true;
        }

        return null; // Fall through to specific methods
    }

    public function createProgram(User $user): bool
    {
        return $user->can('program.create');
    }

    public function updateProgram(User $user, Program $program): bool
    {
        return $user->id === $program->instructor_id;
    }

    public function archiveProgram(User $user, Program $program): bool
    {
        return $user->id === $program->instructor_id;
    }
}
