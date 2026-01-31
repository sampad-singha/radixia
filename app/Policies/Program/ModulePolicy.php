<?php

namespace App\Policies\Program;

use App\Domain\Programs\Entities\Module;
use App\Domain\Programs\Entities\Program;
use App\Models\User;

class ModulePolicy
{
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

        return null;
    }

    public function createModule(User $user, Program $program): bool
    {
        if($user->id !== $program->instructor_id) {
            return false;
        }

        return $user->can('module.create');
    }

    public function updateModule(User $user, Module $module): bool
    {
        return $user->id === $module->program->instructor_id;
    }

    public function reorderModules(User $user, Program $program, array $ids): bool
    {
        if ($user->id !== $program->instructor_id) {
            return false;
        }

        $existingModuleIds = $program->modules()->pluck('id')->toArray();
        sort($ids);
        sort($existingModuleIds);

        return $ids === $existingModuleIds;
    }
}
