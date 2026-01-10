<?php

use App\Http\Controllers\Api\V1\Auth\AuthController;
use App\Http\Controllers\Api\V1\User\EmailChangeController;
use Illuminate\Support\Facades\Route;

// All routes here are scoped to 'v1/user' and require 'auth:sanctum'
Route::prefix('user')->middleware(['auth:sanctum', 'ability:access-api'])->group(function () {

    // ---------------------------------------------------------------------
    // Profile Management
    // ---------------------------------------------------------------------
    // Rate limit profile updates to prevent database spam
    Route::put('/profile-information', [AuthController::class, 'updateProfile'])
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

    // ---------------------------------------------------------------------
    // Test / Debug Routes
    // ---------------------------------------------------------------------
    Route::middleware(['verified', 'sudo'])->get('test', function () {
        return response()->json(['message' => 'Email Verified & Sudo Active, access granted.']);
    });
});
