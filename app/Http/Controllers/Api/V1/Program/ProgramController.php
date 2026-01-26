<?php

namespace App\Http\Controllers\Api\V1\Program;

use App\Domain\Programs\Services\ProgramServiceInterface;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\Program\CreateProgramRequest;
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

    public function getProgramDetails(string $slugOrId)
    {
        $program = $this->programService->getProgramDetails($slugOrId);

        return response()->json([
            'program' => $program,
        ]);
    }

    public function updateProgram(string $id, UpdateProgramRequest $request)
    {
        $program = $this->programService->updateProgram($id, $request->validated());

        return response()->json([
            'message' => 'Program updated successfully.',
            'program' => $program,
        ]);
    }

    public function archiveProgram(string $id)
    {
        $this->programService->archiveProgram($id);

        return response()->json([
            'message' => 'Program archived successfully.',
        ]);
    }

    public function addModuleToProgram(string $programId, CreateProgramRequest $request)
    {
        $module = $this->programService->addModuleToProgram($programId, $request->validated());

        return response()->json([
            'message' => 'Module added to program successfully.',
            'module' => $module,
        ], 201);
    }

    public function updateModule(string $moduleId, CreateProgramRequest $request)
    {
        $module = $this->programService->updateModule($moduleId, $request->validated());

        return response()->json([
            'message' => 'Module updated successfully.',
            'module' => $module,
        ]);
    }

    public function addLessonToModule(string $moduleId, CreateProgramRequest $request)
    {
        $lesson = $this->programService->addLessonToModule($moduleId, $request->validated());

        return response()->json([
            'message' => 'Lesson added to module successfully.',
            'lesson' => $lesson,
        ], 201);
    }


}
