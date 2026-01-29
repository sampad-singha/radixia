<?php

namespace App\Http\Controllers\Api\V1\Program;

use App\Domain\Programs\Exceptions\LessonNotFoundException;
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

class ProgramController extends Controller
{
    public function __construct(
        private readonly ProgramServiceInterface $programService,
    )
    {}

    public function createProgram(CreateProgramRequest $request)
    {
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
        $program = $this->programService->updateProgram($program, $request->validated());

        return response()->json([
            'message' => 'Program updated successfully.',
            'program' => $program,
        ]);
    }

    public function archiveProgram(string $program)
    {
        $program = $this->programService->archiveProgram($program);

        return response()->json([
            'message' => 'Program archived successfully.',
            'data' => $program
        ]);
    }

    public function addModuleToProgram(string $program, CreateModuleRequest $request)
    {
        $module = $this->programService->addModuleToProgram($program, $request->validated());

        return response()->json([
            'message' => 'Module added to program successfully.',
            'module' => $module,
        ], 201);
    }

    public function updateModule(string $module, UpdateModuleRequest $request)
    {
        $module = $this->programService->updateModule($module, $request->validated());

        return response()->json([
            'message' => 'Module updated successfully.',
            'module' => $module,
        ]);
    }

    /**
     * Soft delete a module and its associated lessons.
     */
    public function deleteModule(string $module)
    {
        $this->programService->deleteModule($module);

        return response()->json([
            'message' => 'Module and its lessons have been moved to trash.'
        ]);
    }

    /**
     * Restore a soft-deleted module and its lessons.
     */
    public function restoreModule(string $module)
    {
        $module = $this->programService->restoreModule($module);

        return response()->json([
            'message' => 'Module and its lessons restored successfully.',
            'data' => $module
        ]);
    }

    public function reorderModules(string $program, ReorderModulesRequest $request)
    {
        $this->programService->reorderModules($program, $request->validated()['ids']);

        return response()->json(['message' => 'Curriculum updated successfully']);
    }

    public function addLessonToModule(string $module, CreateLessonRequest $request)
    {
        $lesson = $this->programService->addLessonToModule($module, $request->validated());

        return response()->json([
            'message' => 'Lesson added to module successfully.',
            'lesson' => $lesson,
        ], 201);
    }

    public function updateLesson(string $lesson, UpdateLessonRequest $request)
    {
        $lesson = $this->programService->updateLesson($lesson, $request->validated());

        return response()->json([
            'message' => 'Lesson updated successfully.',
            'lesson' => $lesson,
        ]);
    }

    public function deleteLesson(string $lesson)
    {
        $this->programService->deleteLesson($lesson);

        return response()->json(['message' => 'Lesson deleted successfully']);
    }

    /**
     * @throws LessonNotFoundException
     */
    public function restoreLesson(string $lesson)
    {
        // The Service handles the Smart Restore logic (checking index occupancy)
        $lesson = $this->programService->restoreLesson($lesson);

        return response()->json([
            'message' => 'Lesson restored successfully.',
            'data' => $lesson
        ]);
    }

    public function reorderLessons(string $module, ReorderLessonsRequest $request)
    {
        $this->programService->reorderLessons($module, $request->validated()['ids']);

        return response()->json(['message' => 'Lessons reordered successfully']);
    }


}
