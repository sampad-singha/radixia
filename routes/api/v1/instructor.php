<?php

use App\Http\Controllers\Api\V1\Instructor\InstructorProfileController;
use Illuminate\Support\Facades\Route;

Route::prefix('instructor')->middleware(['auth:sanctum', 'verified', 'ability:access-api'])->group(function () {
    Route::get('/profile', [InstructorProfileController::class, 'show']);
    Route::post('/profile', [InstructorProfileController::class, 'store']);
    Route::put('/profile', [InstructorProfileController::class, 'update']);
});
