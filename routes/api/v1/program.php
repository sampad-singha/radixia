<?php

use App\Http\Controllers\Api\V1\Program\CohortController;
use App\Http\Controllers\Api\V1\Program\ProgramController;
use Illuminate\Support\Facades\Route;

//Route::prefix('programs')->group(function () {
//
//    Route::middleware(['auth:sanctum', 'ability:access-api'])->group(function () {
//
//        Route::post('/', [ProgramController::class, 'createProgram']);
//
//        // 1. LESSONS (Deepest nesting - Must be on top)
//        Route::patch('/{program}/modules/{module}/lessons/reorder', [ProgramController::class, 'reorderLessons']);
//        Route::post('/{program}/modules/{module}/lessons', [ProgramController::class, 'addLessonToModule']);
//        Route::patch('/{program}/modules/{module}/lessons/{lesson}/restore', [ProgramController::class, 'restoreLesson']);
//        Route::put('/{program}/modules/{module}/lessons/{lesson}', [ProgramController::class, 'updateLesson']);
//        Route::delete('/{program}/modules/{module}/lessons/{lesson}', [ProgramController::class, 'deleteLesson']);
//
//        // 2. MODULES (Mid-level nesting)
//        Route::patch('/{program}/modules/reorder', [ProgramController::class, 'reorderModules']);
//        Route::post('/{program}/modules', [ProgramController::class, 'addModuleToProgram']);
//        Route::patch('/{program}/modules/{module}/restore', [ProgramController::class, 'restoreModule']);
//        Route::put('/{program}/modules/{module}', [ProgramController::class, 'updateModule']);
//        Route::delete('/{program}/modules/{module}', [ProgramController::class, 'deleteModule']);
//
//        // 3. PROGRAMS (Top-level)
//        Route::patch('/{program}/archive', [ProgramController::class, 'archiveProgram']);
//        Route::get('/{program}/cohorts', [CohortController::class, 'listCohortsByProgram']);
//        Route::put('/{program}', [ProgramController::class, 'updateProgram']);
//    });
//
//    Route::get('/', [ProgramController::class, 'listPublishedPrograms']);
//    Route::get('/{slugOrId}', [ProgramController::class, 'getProgramDetails']);
//});
//
//Route::prefix('cohorts')->group(function () {
//    Route::middleware(['auth:sanctum', 'ability:access-api'])->group(function () {
//        Route::post('/', [CohortController::class, 'createCohort']);
//
//        Route::put('/{cohort}', [CohortController::class, 'updateCohort']);
//        Route::delete('/{cohort}', [CohortController::class, 'deleteCohort']);
//        Route::patch('/{cohort}/restore', [CohortController::class, 'restoreCohort']);
//    });
//
//    Route::get('/{cohortId}', [CohortController::class, 'getCohortDetails']);
//});

/**
 * SHARED / PUBLIC ROUTES
 * Accessible by both Guests and Authenticated Users
 */
Route::prefix('programs')->group(function () {
    Route::get('/', [ProgramController::class, 'listPublishedPrograms']);
    Route::get('/{program}/cohorts', [CohortController::class, 'listCohortsByProgram']);
    Route::get('/{program}', [ProgramController::class, 'getProgramDetails']);
});

Route::get('cohorts/{cohort}', [CohortController::class, 'getCohortDetails']);


/**
 * INSTRUCTOR ROUTES
 * Logic for managing and creating content
 */
Route::prefix('instructor')->middleware(['auth:sanctum', 'ability:access-api'])->group(function () {

    // Program Management
    Route::prefix('programs')->group(function () {
        Route::post('/', [ProgramController::class, 'createProgram']);
        Route::patch('/{program}', [ProgramController::class, 'updateProgram']);
        Route::patch('/{program}/archive', [ProgramController::class, 'archiveProgram']);

        // Modules (Nesting only for creation/reorder)
        Route::post('/{program}/modules', [ProgramController::class, 'addModuleToProgram']);
        Route::patch('/{program}/modules/reorder', [ProgramController::class, 'reorderModules']);
    });

    // Shallow Module Operations
    Route::prefix('modules/{module}')->group(function () {
        Route::patch('/', [ProgramController::class, 'updateModule']);
        Route::delete('/', [ProgramController::class, 'deleteModule']);
        Route::patch('/restore', [ProgramController::class, 'restoreModule']);

        // Lessons (Nesting only for creation/reorder)
        Route::post('/lessons', [ProgramController::class, 'addLessonToModule']);
        Route::patch('/lessons/reorder', [ProgramController::class, 'reorderLessons']);
    });

    // Shallow Lesson Operations
    Route::prefix('lessons/{lesson}')->group(function () {
        Route::patch('/', [ProgramController::class, 'updateLesson']);
        Route::delete('/', [ProgramController::class, 'deleteLesson']);
        Route::patch('/restore', [ProgramController::class, 'restoreLesson']);
    });

    // Cohort Management
    Route::prefix('cohorts')->group(function () {
        Route::post('/', [CohortController::class, 'createCohort']);
        Route::patch('/{cohort}', [CohortController::class, 'updateCohort']);
        Route::delete('/{cohort}', [CohortController::class, 'deleteCohort']);
        Route::patch('/{cohort}/restore', [CohortController::class, 'restoreCohort']);
    });
});


/**
 * USER (STUDENT) ROUTES
 * Logic for consuming content and self-enrollment
 */
Route::prefix('user')->middleware(['auth:sanctum', 'ability:access-api'])->group(function () {
    // Examples for the future:
    // Route::get('/my-programs', [StudentController::class, 'enrolledPrograms']);
    // Route::post('/cohorts/{cohort}/enroll', [EnrollmentController::class, 'enrollSelf']);
});