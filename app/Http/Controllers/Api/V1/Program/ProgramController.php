<?php

namespace App\Http\Controllers\Api\V1\Program;

use App\Domain\Programs\Entities\Lesson;
use App\Domain\Programs\Entities\Module;
use App\Domain\Programs\Entities\Program;
use App\Domain\Programs\Exceptions\LessonNotFoundException;
use App\Domain\Programs\Exceptions\ModuleNotFoundException;
use App\Domain\Programs\Services\ProgramServiceInterface;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\Program\CreateLessonRequest;
use App\Http\Requests\Api\V1\Program\CreateModuleRequest;
use App\Http\Requests\Api\V1\Program\CreateProgramRequest;
use App\Http\Requests\Api\V1\Program\ReorderLessonsRequest;
use App\Http\Requests\Api\V1\Program\ReorderModulesRequest;
use App\Http\Requests\Api\V1\Program\UpdateLessonRequest;
use App\Http\Requests\Api\V1\Program\UpdateModuleRequest;
use App\Http\Requests\Api\V1\Program\UpdateProgramRequest;
use Gate;
use Illuminate\Support\Facades\Auth;

class ProgramController extends Controller
{
    public function __construct(
        private readonly ProgramServiceInterface $programService,
    )
    {}

    public function createProgram(CreateProgramRequest $request)
    {
        Gate::authorize('createProgram', Program::class);
        $program = $this->programService->createProgram($request->validated());

        return response()->json([
            'message' => 'Program created successfully.',
            'program' => $program,
        ], 201);
    }

    public function listPublishedPrograms()
    {
        $programs = $this->programService->listPublishedPrograms();

        return response()->json([
            'programs' => $programs,
        ]);
    }

    public function getProgramDetails(string $program)
    {
        $program = $this->programService->getProgramDetails($program);

        return response()->json([
            'program' => $program,
        ]);
    }

    public function updateProgram(string $program, UpdateProgramRequest $request)
    {
        $program = $this->programService->getProgramById($program);
        Gate::authorize('updateProgram', $program);
        $program = $this->programService->updateProgram($program, $request->validated());

        return response()->json([
            'message' => 'Program updated successfully.',
            'program' => $program,
        ]);
    }

    public function archiveProgram(string $program)
    {
        $program = $this->programService->getProgramById($program);
        Gate::authorize('archiveProgram', [Program::class, $program]);
        $program = $this->programService->archiveProgram($program);

        return response()->json([
            'message' => 'Program archived successfully.',
            'data' => $program
        ]);
    }

    public function addModuleToProgram(string $program, CreateModuleRequest $request)
    {
        $program = $this->programService->getProgramById($program);
        Gate::authorize('createModule', [Module::class, $program]);
        $module = $this->programService->addModuleToProgram($program, $request->validated());

        return response()->json([
            'message' => 'Module added to program successfully.',
            'module' => $module,
        ], 201);
    }

    /**
     * @throws ModuleNotFoundException
     */
    public function updateModule(string $module, UpdateModuleRequest $request)
    {
        $module = $this->programService->findModuleById($module);
        Gate::authorize('updateModule', $module);
        $module = $this->programService->updateModule($module, $request->validated());

        return response()->json([
            'message' => 'Module updated successfully.',
            'module' => $module,
        ]);
    }

    /**
     * Soft delete a module and its associated lessons.
     * @throws ModuleNotFoundException
     */
    public function deleteModule(string $module)
    {
        $module = $this->programService->findModuleById($module);
        Gate::authorize('updateModule', $module);
        $this->programService->deleteModule($module);

        return response()->json([
            'message' => 'Module and its lessons have been moved to trash.'
        ]);
    }

    /**
     * Restore a soft-deleted module and its lessons.
     * @throws ModuleNotFoundException
     */
    public function restoreModule(string $module)
    {
        $module = $this->programService->findModuleById($module);
        Gate::authorize('updateModule', $module);
        $module = $this->programService->restoreModule($module);

        return response()->json([
            'message' => 'Module and its lessons restored successfully.',
            'data' => $module
        ]);
    }

    public function reorderModules(string $program, ReorderModulesRequest $request)
    {
        $program = $this->programService->getProgramById($program);
        $ids = $request->validated()['ids'];
        Gate::authorize('reorderModules', [Module::class,$program, $ids]);
        $this->programService->reorderModules($program, $ids);

        return response()->json(['message' => 'Curriculum updated successfully']);
    }

    /**
     * @throws ModuleNotFoundException
     */
    public function addLessonToModule(string $module, CreateLessonRequest $request)
    {
        $module = $this->programService->findModuleById($module);
        Gate::authorize('createLesson', [Lesson::class, $module]);
        $lesson = $this->programService->addLessonToModule($module, $request->validated());

        return response()->json([
            'message' => 'Lesson added to module successfully.',
            'lesson' => $lesson,
        ], 201);
    }

    /**
     * @throws LessonNotFoundException
     */
    public function updateLesson(string $lesson, UpdateLessonRequest $request)
    {
        $lesson = $this->programService->findLessonById($lesson);
        Gate::authorize('updateLesson', $lesson);
        $lesson = $this->programService->updateLesson($lesson, $request->validated());

        return response()->json([
            'message' => 'Lesson updated successfully.',
            'lesson' => $lesson,
        ]);
    }

    /**
     * @throws LessonNotFoundException
     */
    public function deleteLesson(string $lesson)
    {
        $lesson = $this->programService->findLessonById($lesson);
        Gate::authorize('updateLesson', $lesson);
        $this->programService->deleteLesson($lesson);

        return response()->json(['message' => 'Lesson deleted successfully']);
    }

    /**
     * @throws LessonNotFoundException
     */
    public function restoreLesson(string $lesson)
    {
        $lesson = $this->programService->findLessonById($lesson);
        Gate::authorize('updateLesson', $lesson);
        $lesson = $this->programService->restoreLesson($lesson);

        return response()->json([
            'message' => 'Lesson restored successfully.',
            'data' => $lesson
        ]);
    }

    /**
     * @throws ModuleNotFoundException
     */
    public function reorderLessons(string $module, ReorderLessonsRequest $request)
    {
        $module = $this->programService->findModuleById($module);
        $ids = $request->validated()['ids'];
        Gate::authorize('reorderLessons', [Lesson::class,$module, $ids]);
        $this->programService->reorderLessons($module, $ids);

        return response()->json(['message' => 'Lessons reordered successfully']);
    }


}
