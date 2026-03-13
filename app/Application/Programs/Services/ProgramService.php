<?php

namespace App\Application\Programs\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use App\Domain\Programs\Entities\{Lesson, Module, Program};
use App\Domain\Programs\Exceptions\{ActiveCohortsException,
    LessonNotFoundException,
    ModuleNotFoundException,
    ProgramNotFoundException};
use App\Domain\Programs\Repositories\{LessonRepositoryInterface, ModuleRepositoryInterface, ProgramRepositoryInterface};
use App\Domain\Programs\Services\ProgramServiceInterface;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Throwable;

readonly class ProgramService implements ProgramServiceInterface
{
    public function __construct(
        private ProgramRepositoryInterface $programRepository,
        private ModuleRepositoryInterface  $moduleRepository,
        private LessonRepositoryInterface  $lessonRepository
    )
    {
    }

    // --- Program CRUD ---

    /**
     * @throws ProgramNotFoundException
     */
    public function getProgramById(string $id): ?Program
    {
        $program =  $this->programRepository->findById($id);
        if(!$program) {
            throw new ProgramNotFoundException();
        }
        return $program;
    }

    public function listPublishedPrograms(): Collection
    {
        // Marketplace list usually changes when any program is created/archived
        return Cache::tags(['programs_list'])->remember('published_programs', now()->addHour(), function () {
            return $this->programRepository->allPublished();
        });
    }

    /**
     * @throws ProgramNotFoundException
     */
    public function getProgramDetails(string $slugOrId): Program
    {
        $cacheKey = "program_details_$slugOrId";

        return Cache::tags(['programs', "program_$slugOrId"])->remember(
            $cacheKey,
            now()->addDays(7),
            fn() => $this->programRepository->findWithCurriculum($slugOrId)
                ?? throw new ProgramNotFoundException()
        );
    }

    public function createProgram(array $data): Program
    {
        $data['instructor_id'] = auth()->id();
        //Generate slug if not provided
        if (empty($data['slug'])) {
            $data['slug'] = Str::slug($data['title']);
        }
        $program = $this->programRepository->create($data);
        Cache::tags(['programs_list'])->flush();
        return $program;
    }

    public function updateProgram(Program $program, array $data): Program
    {
        $changeSlug = $data['change_slug'] ?? false;

        //Generate slug if not provided
        if ($changeSlug) {
            if (empty($data['slug'])) {
                $titleForSlug = $data['title'] ?? $program->title;
                $data['slug'] = Str::slug($titleForSlug);
            } else {
                $data['slug'] = Str::slug($data['slug']);
            }
        } else {
            unset($data['slug']);
        }
        $updated = $this->programRepository->update($program, $data);

        // Invalidate both the list and the specific program cache
        $this->clearProgramCache($updated->id, $updated->slug);
        return $updated;
    }

    /**
     * @throws ActiveCohortsException
     */
    public function archiveProgram(Program $program): Program
    {
        $hasActiveCohorts = $this->programRepository->hasActiveCohorts($program->id);
        if ($hasActiveCohorts) {
            throw new ActiveCohortsException();
        }

        $updated = $this->programRepository->update($program, ['status' => 'archived']);

        $this->clearProgramCache($program->id, $updated->slug);
        return $updated;
    }

    // --- Module CRUD ---

    /**
     * @throws ModuleNotFoundException
     */
    public function findModuleById(string $id): ?Module
    {
        $module = $this->moduleRepository->findWithTrashed($id);
        if(!$module) {
            throw new ModuleNotFoundException();
        }
        return $module;
    }

    public function addModuleToProgram(Program $program, array $data): Module
    {
        $maxIndex = $this->programRepository->getModuleMaxIndex($program->id);
        $data['program_id'] = $program->id;
        $data['order_index'] = $maxIndex + 1;
        $module = $this->moduleRepository->create($data);

        $this->clearProgramCache($program->id, $program->slug);
        return $module;
    }

    public function updateModule(Module $module, array $data): Module
    {
        $updated = $this->moduleRepository->update($module, $data);

        // Find parent program to clear cache
        $this->clearProgramCache($updated->program_id);
        return $updated;
    }

    public function deleteModule(Module $module): void
    {
        // 1. Fetch all active lessons belonging to this module
        $lessons = $this->lessonRepository->findByModule($module->id);

        // 2. Loop and delete using existing repository logic
        // This ensures any logic in your delete() method is respected
        foreach ($lessons as $lesson) {
            $this->lessonRepository->delete($lesson);
        }

        // 3. Soft delete the module itself
        $this->moduleRepository->delete($module);

        $this->clearProgramCache($module->program_id);
    }

    public function restoreModule(Module $module): Module
    {
        // 1. Fetch all trashed lessons for this module
        $trashedLessons = $this->lessonRepository->getTrashedByModuleId($module->id);

        // 2. Loop and restore
        foreach ($trashedLessons as $lesson) {
            $this->lessonRepository->restore($lesson);
        }

        // 3. Handle Module Smart Restore Index
        $isSpotTaken = $this->moduleRepository->isIndexOccupied(
            $module->program_id,
            $module->order_index
        );

        if ($isSpotTaken) {
            $maxIndex = $this->programRepository->getModuleMaxIndex($module->program_id);
            $module->order_index = $maxIndex + 1;
        }

        $this->moduleRepository->restore($module);
        $this->clearProgramCache($module->program_id);

        return $module;
    }

    /**
     * @throws Throwable
     */
    public function reorderModules(Program $program, array $orderedIds): void
    {
        DB::transaction(function () use ($orderedIds) {
            foreach ($orderedIds as $position => $id) {
                $this->moduleRepository->updateOrderIndex($id, $position + 1);
            }
        });

        $this->clearProgramCache($program->id);
    }

    // --- Lesson CRUD ---

    /**
     * @throws LessonNotFoundException
     */
    public function findLessonById(string $id): ?Lesson
    {
        $lesson = $this->lessonRepository->findWithTrashed($id);
        if(!$lesson)
        {
            throw new LessonNotFoundException();
        }
        return $lesson;
    }

    public function addLessonToModule(Module $module, array $data): Lesson
    {
        $maxIndex = $this->moduleRepository->getLessonMaxIndex($module->id);
        $data['module_id'] = $module->id;
        $data['order_index'] = $maxIndex + 1;
        $lesson = $this->lessonRepository->create($data);

        $this->clearProgramCache($module->program_id);
        return $lesson;
    }

    public function updateLesson(Lesson $lesson, array $data): Lesson
    {
        $updated = $this->lessonRepository->update($lesson, $data);

        $this->clearProgramCache($updated->module->program_id);
        return $updated;
    }

    public function deleteLesson(Lesson $lesson): void
    {
        // Get parent ID before deleting to clear cache
        $module = $this->moduleRepository->findById($lesson->module_id);

        $this->lessonRepository->delete($lesson);

        if ($module) {
            $this->clearProgramCache($module->program_id);
        }
    }

    /**
     * @throws Throwable
     */
    public function reorderLessons(Module $module, array $orderedIds): void
    {
        DB::transaction(function () use ($orderedIds) {
            foreach ($orderedIds as $position => $id) {
                $this->lessonRepository->updateOrderIndex($id, $position + 1);
            }
        });

        $this->clearProgramCache($module->program_id);
    }

    public function restoreLesson(Lesson $lesson): Lesson
    {
        // 1. Check if the original spot is taken by a live lesson
        $isSpotTaken = $this->lessonRepository->isIndexOccupied(
            $lesson->module_id,
            $lesson->order_index
        );

        if ($isSpotTaken) {
            // Spot is taken! Move to the end to avoid collision
            $maxIndex = $this->moduleRepository->getLessonMaxIndex($lesson->module_id);
            $lesson->order_index = $maxIndex + 1;
        }
        // If NOT taken, we leave $lesson->order_index exactly as it was.

        // 2. Restore
        $this->lessonRepository->restore($lesson);

        // 3. Cleanup & Cache
        $module = $this->moduleRepository->findById($lesson->module_id);
        $this->clearProgramCache($module->program_id);

        return $lesson;
    }

    /**
     * Helper to handle multi-tag invalidation
     */
    private function clearProgramCache(string $id, ?string $slug = null): void
    {
        Cache::tags(["program_$id"])->flush();
        if ($slug) {
            Cache::tags(["program_$slug"])->flush();
        }
        Cache::tags(['programs_list'])->flush();
    }
}
