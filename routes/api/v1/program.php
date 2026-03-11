<?php

use App\Http\Controllers\Api\V1\Meetings\MeetingWebhookController;
use App\Http\Controllers\Api\V1\Program\AttendanceController;
use App\Http\Controllers\Api\V1\Program\CohortController;
use App\Http\Controllers\Api\V1\Program\CohortSessionController;
use App\Http\Controllers\Api\V1\Program\ProgramController;
use App\Http\Middleware\VerifyJaasSignature;
use Illuminate\Support\Facades\Route;


/*
|--------------------------------------------------------------------------
| PUBLIC ROUTES
|--------------------------------------------------------------------------
| Accessible by guests and authenticated users
*/

Route::prefix('programs')->group(function () {
    Route::get('/', [ProgramController::class, 'listPublishedPrograms']);
    Route::get('{program}', [ProgramController::class, 'getProgramDetails']);
    Route::get('{program}/cohorts', [CohortController::class, 'listCohortsByProgram']);
});
Route::prefix('cohorts')->group(function () {
    Route::get('{cohort}/sessions', [CohortSessionController::class, 'listSessionsByCohort']);
});

Route::get('cohorts/{cohort}', [CohortController::class, 'getCohortDetails']);

/*
|--------------------------------------------------------------------------
| AUTHENTICATED ROUTES
|--------------------------------------------------------------------------
*/

Route::middleware(['auth:sanctum', 'ability:access-api'])->group(function () {

    /*
    |--------------------------------------------------------------------------
    | PROGRAM MANAGEMENT
    |--------------------------------------------------------------------------
    */

    Route::prefix('programs')->group(function () {
        Route::post('/', [ProgramController::class, 'createProgram']);
        Route::patch('{program}', [ProgramController::class, 'updateProgram']);
        Route::patch('{program}/archive', [ProgramController::class, 'archiveProgram']);
        Route::post('{program}/modules', [ProgramController::class, 'addModuleToProgram']);
        Route::patch('{program}/modules/reorder', [ProgramController::class, 'reorderModules']);
    });


    /*
    |--------------------------------------------------------------------------
    | MODULE MANAGEMENT
    |--------------------------------------------------------------------------
    */

    Route::prefix('modules/{module}')->group(function () {
        Route::patch('/', [ProgramController::class, 'updateModule']);
        Route::delete('/', [ProgramController::class, 'deleteModule']);
        Route::patch('/restore', [ProgramController::class, 'restoreModule']);
        Route::post('/lessons', [ProgramController::class, 'addLessonToModule']);
        Route::patch('/lessons/reorder', [ProgramController::class, 'reorderLessons']);
    });


    /*
    |--------------------------------------------------------------------------
    | LESSON MANAGEMENT
    |--------------------------------------------------------------------------
    */

    Route::prefix('lessons/{lesson}')->group(function () {
        Route::patch('/', [ProgramController::class, 'updateLesson']);
        Route::delete('/', [ProgramController::class, 'deleteLesson']);
        Route::patch('/restore', [ProgramController::class, 'restoreLesson']);
    });


    /*
    |--------------------------------------------------------------------------
    | COHORT MANAGEMENT
    |--------------------------------------------------------------------------
    */

    Route::prefix('cohorts')->group(function () {
        Route::post('/', [CohortController::class, 'createCohort']);
        Route::patch('{cohort}', [CohortController::class, 'updateCohort']);
        Route::delete('{cohort}', [CohortController::class, 'deleteCohort']);
        Route::patch('{cohort}/restore', [CohortController::class, 'restoreCohort']);
    });


    /*
    |--------------------------------------------------------------------------
    | COHORT SESSIONS
    |--------------------------------------------------------------------------
    */

    Route::prefix('cohort-sessions')->group(function () {
        Route::get('{id}', [CohortSessionController::class, 'show']);
        Route::post('/', [CohortSessionController::class, 'store']);
        Route::patch('{id}', [CohortSessionController::class, 'update']);
        Route::delete('{id}', [CohortSessionController::class, 'destroy']);
        Route::patch('{id}/restore', [CohortSessionController::class, 'restore']);
        Route::post('{id}/complete', [CohortSessionController::class, 'complete']);
        Route::post('{id}/cancel', [CohortSessionController::class, 'cancel']);
        Route::post('{id}/join', [CohortSessionController::class, 'join']);
    });


    /*
    |--------------------------------------------------------------------------
    | ATTENDANCE
    |--------------------------------------------------------------------------
    */

    Route::prefix('attendance')->group(function () {
        Route::get('sessions/{session}', [AttendanceController::class, 'getSessionAttendance']);
        Route::get('sessions/{session}/summary', [AttendanceController::class, 'getSessionSummary']);
        Route::get('cohorts/{cohort}', [AttendanceController::class, 'getCohortAttendance']);
        Route::get('cohorts/{cohort}/students/{user}', [AttendanceController::class, 'getStudentAttendance']);
        Route::get('cohorts/{cohort}/summary', [AttendanceController::class, 'getCohortSummary']);
    });
});


/*
|--------------------------------------------------------------------------
| EXTERNAL WEBHOOKS
|--------------------------------------------------------------------------
*/

Route::post('/webhooks/jaas', [
    MeetingWebhookController::class,
    'handleMeetWebhook'
])->middleware(VerifyJaasSignature::class);
