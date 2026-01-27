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

    /**
     * @throws ProgramNotFoundException
     */
    public function updateProgram(string $id, array $data): Program
    {
        $program = $this->programRepository->findById($id);
        if (!$program)
        {
            throw new ProgramNotFoundException();
        }

        //Generate slug if not provided
        if ($data['change_slug']) {
            if (empty($data['slug'])) {
                $titleForSlug = $data['title'] ?? $program->title;
                $data['slug'] = Str::slug($titleForSlug);
            } else {
                $data['slug'] = Str::slug($data['slug']);
            }
        }else{
            unset($data['slug']);
        }
        $updated = $this->programRepository->update($program, $data);

        // Invalidate both the list and the specific program cache
        $this->clearProgramCache($id, $updated->slug);
        return $updated;
    }

    /**
     * @throws ProgramNotFoundException
     * @throws ActiveCohortsException
     */
    public function archiveProgram(string $id): Program
    {
        $program = $this->programRepository->findById($id);
        if (!$program) {
            throw new ProgramNotFoundException();
        }

        $hasActiveCohorts = $this->programRepository->hasActiveCohorts($id);
        if ($hasActiveCohorts) {
            throw new ActiveCohortsException();
        }

        $updated = $this->programRepository->update($program, ['status' => 'archived']);

        $this->clearProgramCache($id, $updated->slug);
        return $updated;
    }

    // --- Module CRUD ---

    /**
     * @throws ProgramNotFoundException
     */
    public function addModuleToProgram(string $programId, array $data): Module
    {
        $program = $this->programRepository->findById($programId);
        if (!$program)
        {
            throw new ProgramNotFoundException();
        }

        $maxIndex = $this->programRepository->getModuleMaxIndex($programId);
        $data['program_id'] = $programId;
        $data['order_index'] = $maxIndex + 1;
        $module = $this->moduleRepository->create($data);

        $this->clearProgramCache($programId, $program->slug);
        return $module;
    }

    /**
     * @throws ModuleNotFoundException
     */
    public function updateModule(string $moduleId, array $data): Module
    {
        $module = $this->moduleRepository->findById($moduleId);
        if (!$module)
        {
            throw new ModuleNotFoundException();
        }

        $updated = $this->moduleRepository->update($module, $data);

        // Find parent program to clear cache
        $this->clearProgramCache($updated->program_id);
        return $updated;
    }

    /**
     * @throws Throwable
     */
    public function reorderModules(string $programId, array $orderedIds): void
    {
        DB::transaction(function () use ($orderedIds) {
            foreach ($orderedIds as $position => $id) {
                $this->moduleRepository->updateOrderIndex($id, $position + 1);
            }
        });

        $this->clearProgramCache($programId);
    }

    // --- Lesson CRUD ---

    /**
     * @throws ModuleNotFoundException
     */
    public function addLessonToModule(string $moduleId, array $data): Lesson
    {
        $module = $this->moduleRepository->findById($moduleId);
        if (!$module)
        {
            throw new ModuleNotFoundException();
        }

        $maxIndex = $this->moduleRepository->getLessonMaxIndex($moduleId);
        $data['module_id'] = $moduleId;
        $data['order_index'] = $maxIndex + 1;
        $lesson = $this->lessonRepository->create($data);

        $this->clearProgramCache($module->program_id);
        return $lesson;
    }

    /**
     * @throws LessonNotFoundException
     */
    public function updateLesson(string $lessonId, array $data): Lesson
    {
        $lesson = $this->lessonRepository->findById($lessonId);
        if(!$lesson)
        {
            throw new LessonNotFoundException();
        }
        $updated = $this->lessonRepository->update($lesson, $data);

        $this->clearProgramCache($updated->module->program_id);
        return $updated;
    }

    /**
     * @throws LessonNotFoundException
     */
    public function deleteLesson(string $lessonId): void
    {
        $lesson = $this->lessonRepository->findById($lessonId);
        if (!$lesson)
        {
            throw new LessonNotFoundException();
        }

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
    public function reorderLessons(string $moduleId, array $orderedIds): void
    {
        DB::transaction(function () use ($orderedIds) {
            foreach ($orderedIds as $position => $id) {
                $this->lessonRepository->updateOrderIndex($id, $position + 1);
            }
        });

        $module = $this->moduleRepository->findById($moduleId);

        $this->clearProgramCache($module->program_id);
    }

    /**
     * @throws LessonNotFoundException
     */
    public function restoreLesson(string $lessonId): Lesson
    {
        $lesson = $this->lessonRepository->findWithTrashed($lessonId);

        if (!$lesson) {
            throw new LessonNotFoundException();
        }

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