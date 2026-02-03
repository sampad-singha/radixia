<?php

namespace App\Policies\Program;

use App\Domain\Programs\Entities\Lesson;
use App\Domain\Programs\Entities\Module;
use App\Models\User;

class LessonPolicy
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
        if ($user->isadmin()) {
            return true;
        }

        return null;
    }

    public function createLesson(User $user, Module $module): bool
    {
        if($user->id !== $module->program->instructor_id) {
            return false;
        }

        return $user->can('lesson.create');
    }

    public function updateLesson(User $user,Lesson $lesson): bool
    {
        return $user->id === $lesson->module->program->instructor_id;
    }

    public function reorderLessons(User $user, Module $module, array $ids): bool
    {
        if ($user->id !== $module->program->instructor_id) {
            return false;
        }

        $existingLessonIds = $module->lessons()->pluck('id')->toArray();
        sort($ids);
        sort($existingLessonIds);

        return $ids === $existingLessonIds;
    }
}
