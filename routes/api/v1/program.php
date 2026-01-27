<?php

use App\Http\Controllers\Api\V1\Program\ProgramController;
use Illuminate\Support\Facades\Route;

Route::prefix('programs')->group(function () {

    Route::middleware(['auth:sanctum', 'ability:access-api'])->group(function () {

        Route::post('/', [ProgramController::class, 'createProgram']);

        // 1. LESSONS (Deepest nesting - Must be on top)
        Route::patch('/{program}/modules/{module}/lessons/reorder', [ProgramController::class, 'reorderLessons']);
        Route::post('/{program}/modules/{module}/lessons', [ProgramController::class, 'addLessonToModule']);
        Route::patch('/{program}/modules/{module}/lessons/{lesson}/restore', [ProgramController::class, 'restoreLesson']);
        Route::put('/{program}/modules/{module}/lessons/{lesson}', [ProgramController::class, 'updateLesson']);
        Route::delete('/{program}/modules/{module}/lessons/{lesson}', [ProgramController::class, 'deleteLesson']);

        // 2. MODULES (Mid-level nesting)
        // Note: Reorder is above the generic /{module} to prevent conflicts
        Route::patch('/{program}/modules/reorder', [ProgramController::class, 'reorderModules']);
        Route::post('/{program}/modules', [ProgramController::class, 'addModuleToProgram']);

        // This generic {module} wildcard is now BELOW the specific /lessons/reorder path
        Route::put('/{program}/modules/{module}', [ProgramController::class, 'updateModule']);

        // 3. PROGRAMS (Top-level)
        Route::patch('/{program}/archive', [ProgramController::class, 'archiveProgram']);
        Route::put('/{program}', [ProgramController::class, 'updateProgram']);
    });

    Route::get('/', [ProgramController::class, 'listPublishedPrograms']);
    Route::get('/{slugOrId}', [ProgramController::class, 'getProgramDetails']);
});