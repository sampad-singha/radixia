<?php

use App\Http\Controllers\Api\V1\Auth\AuthController;
use App\Http\Controllers\Api\V1\Auth\AuthSessionController;
use App\Http\Controllers\Api\V1\Auth\SocialAuthController;
use App\Http\Controllers\Api\V1\Auth\TwoFactorController;
use Illuminate\Support\Facades\Route;

Route::prefix('auth')->group(function () {

    // ---------------------------------------------------------------------
    // Guest / Public Routes (Strictly Throttled)
    // ---------------------------------------------------------------------
    // 'throttle:5,1' allows 5 attempts per minute per IP
    Route::middleware('throttle:5,1')->group(function () {
        Route::post('register', [AuthController::class, 'register']);
        Route::post('login', [AuthController::class, 'login'])->middleware('throttle:login');
        Route::post('forgot-password', [AuthController::class, 'forgotPassword']);
        Route::post('reset-password', [AuthController::class, 'resetPassword'])->name('password.reset');

        // Social Authentication Routes
        Route::prefix('social')->group(function () {
            Route::post('{provider}/callback', [SocialAuthController::class, 'callback']);
        });
    });

    // Email Verification (Signed URL)
    Route::get('/email/verify/{id}/{hash}', [AuthController::class, 'verifyEmail'])
        ->middleware(['throttle:6,1', 'signed'])
        ->name('verification.verify');

    // ---------------------------------------------------------------------
    // Authenticated Routes (Sanctum)
    // ---------------------------------------------------------------------
    Route::middleware(['auth:sanctum', 'ability:access-api'])->group(function () {
        Route::post('logout', [AuthController::class, 'logout']);
        Route::get('me', [AuthController::class, 'me']);

        // Verification Notification
        Route::post('/email/verification-notification', [AuthController::class, 'resendVerification'])
            ->middleware(['throttle:6,1'])
            ->name('verification.send');

        // Password Confirmation (Sudo Mode Entry)
        // STRICT THROTTLING REQUIRED: Prevents brute-forcing the password to gain sudo access
        Route::get('/get-sudo-user', [AuthController::class, 'getSudoUser']);
        Route::post('/confirm-sudo', [AuthController::class, 'confirmSudo'])
            ->middleware('throttle:5,1');

        // Change Password
        // Should require email verification first
        Route::post('/change-password', [AuthController::class, 'changePassword'])
            ->middleware('verified');

        Route::post('/set-password', [AuthController::class, 'setPassword']);
    });

    // Multi-Factor Authentication during Login
    Route::middleware(['auth:sanctum', 'ability:mfa:verify'])->group(function () {
        Route::post('/verify-login', [TwoFactorController::class, 'verifyLogin']);

        Route::post('challenge', [TwoFactorController::class, 'challenge']);
    });

    // ---------------------------------------------------------------------
    // Two-Factor Authentication (Sudo Protected + Verified)
    // ---------------------------------------------------------------------
    // Requires: Logged in + Verified Email + Sudo Mode (Recent Password Confirm)
    Route::middleware(['auth:sanctum', 'verified', 'ability:access-api'])
        ->prefix('two-factor')
        ->group(function () {

            // Enable/Confirm: Strict throttling to prevent code guessing
            Route::post('/enable', [TwoFactorController::class, 'enable']);
            Route::post('/confirm', [TwoFactorController::class, 'confirm'])
                ->middleware('throttle:5,1');

            Route::delete('/', [TwoFactorController::class, 'disable'])
                ->middleware(['sudo']);
            Route::get('/recovery-codes', [TwoFactorController::class, 'recoveryCodes']);
            Route::post('/recovery-codes', [TwoFactorController::class, 'regenerateRecoveryCodes'])
                ->middleware('throttle:5,1');
        });

    // ---------------------------------------------------------------------
    // Session Management
    // ---------------------------------------------------------------------
    Route::prefix('sessions')->middleware(['auth:sanctum', 'ability:access-api'])->group(function () {
        Route::get('/', [AuthSessionController::class, 'index']);
        Route::delete('/{tokenId}', [AuthSessionController::class, 'destroy']);

        // Nuke other sessions: Critical action, requires Sudo
        Route::delete('/', [AuthSessionController::class, 'destroyOthers'])->middleware('sudo');
    });
});
