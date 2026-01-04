<?php

use App\Domain\Auth\Exceptions\EmailAlreadyVerifiedException;
use App\Domain\Auth\Exceptions\EmailVerificationException;
use App\Domain\Auth\Exceptions\InvalidCredentialsException;
use App\Domain\Auth\Exceptions\InvalidResetClientException;
use App\Domain\Auth\Exceptions\InvalidTwoFactorCodeException;
use App\Domain\Auth\Exceptions\PasswordChangeException;
use App\Domain\Auth\Exceptions\PasswordConfirmationException;
use App\Domain\Auth\Exceptions\PasswordResetException;
use App\Domain\Auth\Exceptions\PasswordResetLinkException;
use App\Domain\Auth\Exceptions\TwoFactorNotConfirmedException;
use App\Domain\Auth\Exceptions\TwoFactorNotEnabledException;
use App\Domain\Auth\Exceptions\TwoFactorRequiredException;
use App\Domain\Users\Exceptions\InvalidEmailChangeTokenException;
use App\Http\Middleware\EnsureEmailIsVerifiedApi;
use App\Http\Middleware\EnsureSudoMode;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\Password;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->alias([
            'sudo' => EnsureSudoMode::class,
            'verified' => EnsureEmailIsVerifiedApi::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->render(function (ValidationException $e, Request $request) {
            return response()->json([
                'message' => 'Validation failed.',
                'code' => 'VALIDATION_ERROR',
                'errors' => $e->errors(),
            ], 422);
        });

        $exceptions->render(function (InvalidCredentialsException $e, $request) {
            return response()->json([
                'message' => $e->getMessage(),
                'code'    => 'INVALID_CREDENTIALS',
                'errors' => (object) [],
            ], 401);
        });

        $exceptions->render(function (PasswordResetLinkException $e) {

            return match ($e->brokerStatus()) {
                Password::RESET_THROTTLED => response()->json([
                    'message' => 'Too many reset requests. Please try again later.',
                    'code' => 'PASSWORD_RESET_LINK_THROTTLED',
                ], 429),

                Password::INVALID_USER => response()->json([
                    'message' => 'If the email exists, a reset link will be sent.',
                    'code' => 'PASSWORD_RESET_LINK_SENT',
                ], 200), // To prevent revealing user existence

                default => response()->json([
                    'message' => 'Unable to send reset link.',
                    'code' => 'PASSWORD_RESET_LINK_FAILED',
                ], 400),
            };
        });

        $exceptions->render(function (InvalidResetClientException $e, Request $request) {
            return response()->json([
                'message' => 'Invalid reset client.',
                'code' => 'INVALID_RESET_CLIENT',
                'error' => $e->getMessage()
            ], 400);
        });

        $exceptions->render(function (PasswordResetException $e) {
            return match ($e->brokerStatus()) {

                Password::INVALID_TOKEN => response()->json([
                    'message' => 'This password reset link is invalid or expired.',
                    'code' => 'PASSWORD_RESET_TOKEN_INVALID',
                ], 410),

                Password::INVALID_USER => response()->json([
                    'message' => 'User not found.',
                    'code' => 'PASSWORD_RESET_USER_INVALID',
                ], 404),

                Password::RESET_THROTTLED => response()->json([
                    'message' => 'Too many reset attempts.',
                    'code' => 'PASSWORD_RESET_THROTTLED',
                ], 429),

                default => response()->json([
                    'message' => 'Password reset failed.',
                    'code' => 'PASSWORD_RESET_FAILED',
                ], 410),
            };
        });

        $exceptions->render(function (EmailVerificationException $e, Request $request) {
            return response()->json([
                'message' => $e->getMessage(),
                'code' => "EMAIL_VERIFICATION_LINK_INVALID",
            ], 410);
        });

        $exceptions->render(function (EmailAlreadyVerifiedException $e, Request $request) {
            return response()->json([
                'message' => $e->getMessage(),
                'code' => "EMAIL_ALREADY_VERIFIED",
            ], 409);
        });

        $exceptions->render(function (PasswordConfirmationException $e, Request $request) {
            return response()->json([
                'message' => $e->getMessage(),
                'code' => "PASSWORD_MISMATCH",
                'errors' => [
                    'password' => [$e->getMessage()]
                ]
            ], 403);
        });

        $exceptions->render(function (TwoFactorRequiredException $e, Request $request) {
            return response()->json([
                'message' => $e->getMessage(),
                'code' => "TWO_FACTOR_REQUIRED",
                'two_factor_required' => true,
            ], 423);
        });

        $exceptions->render(function (InvalidTwoFactorCodeException $e, Request $request) {
            return response()->json([
                'message' => $e->getMessage(),
                'code' => "INVALID_TWO_FACTOR_CODE",
                'errors' => [
                    'two_factor_code' => [$e->getMessage()]
                ]
            ], 422);
        });

        $exceptions->render(function (TwoFactorNotConfirmedException $e, Request $request) {
            return response()->json([
                'message' => $e->getMessage(),
                "code" => "TWO_FACTOR_NOT_CONFIRMED",
                'errors' => [
                    'two_factor_status' => [$e->getMessage()]
                ]
            ], 409);
        });

        $exceptions->render(function (TwoFactorNotEnabledException $e, Request $request) {
            return response()->json([
                'message' => $e->getMessage(),
                "code" => "TWO_FACTOR_NOT_ENABLED",
                'errors' => [
                    'two_factor_status' => [$e->getMessage()]
                ]
            ], 409);
        });

        $exceptions->render(function (InvalidEmailChangeTokenException $e, Request $request) {
            return response()->json([
                'message' => $e->getMessage(),
                'code' => 'INVALID_EMAIL_VERIFICATION_TOKEN',
                'errors' => [
                    'verification_code' => [$e->getMessage()]
                ]
            ], 422);
        });

        $exceptions->render(function (PasswordChangeException $e, Request $request) {
            return response()->json([
                'message' => 'Password change failed.',
                'code' => 'PASSWORD_CHANGE_FAILED',
                'error' => $e->getMessage(),
            ], 400);
        });


    })->create();
