<?php

use App\Http\Controllers\Api\V1\Auth\AuthController;
use App\Http\Controllers\Api\V1\Auth\TwoFactorController;
use Illuminate\Support\Facades\Route;

// --- Auth Routes ---
Route::prefix('v1/auth')->group(function () {
    // Guest
    Route::post('register', [AuthController::class, 'register']);
    Route::post('login', [AuthController::class, 'login']);
    Route::post('forgot-password', [AuthController::class, 'forgotPassword']);
    Route::post('reset-password', [AuthController::class, 'resetPassword'])->name('password.reset');

    // Email Verification (Public/Signed)
    Route::get('/email/verify/{id}/{hash}', [AuthController::class, 'verifyEmail'])
        ->middleware(['throttle:6,1', 'signed'])
        ->name('verification.verify');

    // Authenticated Auth Actions
    Route::middleware('auth:sanctum')->group(function () {
        Route::post('logout', [AuthController::class, 'logout']);
        Route::get('me', [AuthController::class, 'me']);

        Route::post('/email/verification-notification', [AuthController::class, 'resendVerification'])
            ->middleware(['throttle:6,1'])
            ->name('verification.send');

        Route::get('/confirmed-password-status', [AuthController::class, 'confirmedPasswordStatus']);
        Route::post('/confirm-password', [AuthController::class, 'confirmPassword']);
    });

    // Two-Factor Authentication Routes
    Route::middleware(['auth:sanctum', 'sudo'])->prefix('two-factor')->group(function () {
        Route::post('/enable', [TwoFactorController::class, 'enable']);
        Route::post('/confirm', [TwoFactorController::class, 'confirm']);
        Route::delete('/', [TwoFactorController::class, 'disable']);
        Route::get('/recovery-codes', [TwoFactorController::class, 'recoveryCodes']);
        Route::post('/recovery-codes', [TwoFactorController::class, 'regenerateRecoveryCodes']);
    });
});

// --- User Resource Routes ---
Route::prefix('v1/user')->middleware('auth:sanctum')->group(function () {
    // Profile Management
    // URL: PUT /api/v1/user/profile-information
    Route::put('/profile-information', [AuthController::class, 'updateProfile']);

    // URL: PUT /api/v1/user/password
    Route::put('/password', [AuthController::class, 'updatePassword']);

    // Verified Only Section
    Route::middleware(['verified', 'sudo'])->group(function () {
        Route::get('test', function () {
            return response()->json(['message' => 'Email Verified, access granted.']);
        });
    });
});
