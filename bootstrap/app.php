<?php

use App\Domain\Auth\Exceptions\EmailAlreadyVerifiedException;
use App\Domain\Auth\Exceptions\EmailVerificationException;
use App\Domain\Auth\Exceptions\InvalidCredentialsException;
use App\Domain\Auth\Exceptions\PasswordConfirmationException;
use App\Domain\Auth\Exceptions\PasswordResetException;
use App\Domain\Auth\Exceptions\PasswordResetLinkException;
use App\Http\Middleware\EnsureSudoMode;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;

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
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->render(function (InvalidCredentialsException $e, $request) {
            return response()->json([
                'message' => $e->getMessage(),
                'errors' => (object) [],
            ], 401);
        });
        $exceptions->render(function (PasswordResetLinkException $e, Request $request) {
            return response()->json([
                'message' => 'Unable to send reset link.',
                'error' => $e->getMessage()
            ], 400);
        });

        $exceptions->render(function (PasswordResetException $e, Request $request) {
            return response()->json([
                'message' => 'Password reset failed.',
                'error' => $e->getMessage()
            ], 400);
        });

        $exceptions->render(function (EmailVerificationException $e, Request $request) {
            return response()->json([
                'message' => $e->getMessage(),
            ], 400);
        });

        $exceptions->render(function (EmailAlreadyVerifiedException $e, Request $request) {
            return response()->json([
                'message' => $e->getMessage(),
            ], 400); // or 409 for conflict
        });

        $exceptions->render(function (PasswordConfirmationException $e, Request $request) {
            return response()->json([
                'message' => $e->getMessage(),
                'errors' => [
                    'password' => [$e->getMessage()]
                ]
            ], $e->getCode());
        });

    })->create();
