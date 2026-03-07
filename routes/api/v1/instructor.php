<?php

use App\Http\Controllers\Api\V1\Instructor\InstructorProfileController;
use Illuminate\Support\Facades\Route;

Route::prefix('instructor')->middleware(['auth:sanctum', 'verified', 'ability:access-api'])->group(function () {
    Route::prefix('profile')->group(function () {
        Route::get('/', [InstructorProfileController::class, 'show']);

        Route::middleware('throttle:6,1')->group(function () {
            Route::post('/', [InstructorProfileController::class, 'store']);
            Route::put('/', [InstructorProfileController::class, 'update']);
        });
    });
});
