<?php

use App\Http\Controllers\Api\V1\Auth\AuthController;
use App\Http\Controllers\Api\V1\Auth\AuthSessionController;
use App\Http\Controllers\Api\V1\Auth\TwoFactorController;
use App\Http\Controllers\Api\V1\User\EmailChangeController;
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

        Route::post('/change-password', [AuthController::class, 'changePassword']);
    });

    // Two-Factor Authentication Routes
    Route::middleware(['auth:sanctum', 'sudo'])->prefix('two-factor')->group(function () {
        Route::post('/enable', [TwoFactorController::class, 'enable']);
        Route::post('/confirm', [TwoFactorController::class, 'confirm']);
        Route::delete('/', [TwoFactorController::class, 'disable']);
        Route::get('/recovery-codes', [TwoFactorController::class, 'recoveryCodes']);
        Route::post('/recovery-codes', [TwoFactorController::class, 'regenerateRecoveryCodes']);
    });

    // Auth Session Management
    Route::prefix('sessions')->middleware('auth:sanctum')->group(function () {
        // List all sessions
        Route::get('/', [AuthSessionController::class, 'index']);

        // Revoke a specific session
        Route::delete('/{tokenId}', [AuthSessionController::class, 'destroy']);

        // Revoke all OTHER sessions (Requires Password Confirmation)
        Route::delete('/', [AuthSessionController::class, 'destroyOthers'])->middleware('sudo');
    });
});

// --- User Resource Routes ---
Route::prefix('v1/user')->middleware('auth:sanctum')->group(function () {
    // Profile Management
    Route::put('/profile-information', [AuthController::class, 'updateProfile']);
    Route::put('/password', [AuthController::class, 'updatePassword']);
    Route::middleware(['verified', 'sudo'])->group(function () {
        Route::get('test', function () {
            return response()->json(['message' => 'Email Verified, access granted.']);
        });
    });

    Route::prefix('email')->group(function () {
        Route::post('/', [EmailChangeController::class, 'store'])
            ->middleware('sudo')
            ->name('user.email.request');

        Route::post('/verify', [EmailChangeController::class, 'verify'])
            ->name('user.email.verify');
    });
});
