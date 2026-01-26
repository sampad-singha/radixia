<?php

namespace App\Application\Programs\Services;

use Illuminate\Support\Str;
use App\Domain\Programs\Entities\{Lesson, Module, Program};
use App\Domain\Programs\Exceptions\{LessonNotFoundException, ModuleNotFoundException, ProgramNotFoundException};
use App\Domain\Programs\Repositories\{LessonRepositoryInterface, ModuleRepositoryInterface, ProgramRepositoryInterface};
use App\Domain\Programs\Services\ProgramServiceInterface;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;

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
     */
    public function archiveProgram(string $id): Program
    {
        $program = $this->programRepository->findById($id);
        if (!$program)
        {
            throw new ProgramNotFoundException();
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

        $data['program_id'] = $programId;
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

        $data['module_id'] = $moduleId;
        $lesson = $this->lessonRepository->create($data);

        $this->clearProgramCache($module->program_id);
        return $lesson;
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