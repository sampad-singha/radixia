<?php

use App\Http\Controllers\Api\V1\Auth\AuthController;
use App\Http\Controllers\Api\V1\User\EmailChangeController;
use App\Http\Controllers\Api\V1\User\UserProfileController;
use Illuminate\Support\Facades\Route;

// All routes here are scoped to 'v1/user' and require 'auth:sanctum'
Route::prefix('user')->middleware(['auth:sanctum', 'ability:access-api'])->group(function () {

    // ---------------------------------------------------------------------
    // Profile Management
    // ---------------------------------------------------------------------
    // Rate limit profile updates to prevent database spam
    Route::put('/account', [AuthController::class, 'updateAccount'])
        ->middleware('throttle:6,1');

    // ---------------------------------------------------------------------
    // Email Change Workflow
    // ---------------------------------------------------------------------
    Route::prefix('email')->group(function () {

        // Request New Email: Strict security (Verified + Sudo + Strict Throttle)
        Route::post('/', [EmailChangeController::class, 'store'])
            ->middleware(['verified', 'sudo', 'throttle:3,1'])
            ->name('user.email.request');

        // Verify New Email Code: Throttle to prevent guessing
        Route::post('/verify', [EmailChangeController::class, 'verify'])
            ->middleware('throttle:5,1')
            ->name('user.email.verify');
    });

    Route::prefix('profile')->group(function () {
        Route::get('/', [UserProfileController::class, 'show']);
        Route::put('/', [UserProfileController::class, 'update']);
    });

    // ---------------------------------------------------------------------
    // Test / Debug Routes
    // ---------------------------------------------------------------------
    if (App::environment(['local', 'testing'])) {
        Route::middleware(['verified', 'sudo'])->get('test', function () {
            return response()->json(['message' => 'Email Verified & Sudo Active, access granted.']);
        });
    }
});
