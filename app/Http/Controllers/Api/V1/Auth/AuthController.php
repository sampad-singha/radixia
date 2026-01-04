<?php

namespace App\Http\Controllers\Api\V1\Auth;

use App\Actions\Fortify\UpdateUserPassword;
use App\Actions\Fortify\UpdateUserProfileInformation;
use App\Domain\Auth\Services\AuthServiceInterface;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\Auth\ConfirmPasswordRequest;
use App\Http\Requests\Api\V1\Auth\ForgotPasswordRequest;
use App\Http\Requests\Api\V1\Auth\LoginRequest;
use App\Http\Requests\Api\V1\Auth\RegisterRequest;
use App\Http\Requests\Api\V1\Auth\ResetPasswordRequest;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function __construct(private readonly AuthServiceInterface $auth) {}

    public function register(RegisterRequest $request): JsonResponse
    {
        $result = $this->auth->register(
            $request->validated(),
            $request->ip(),
            $request->userAgent()
        );

        return response()->json([
            'data' => [
                'token' => $result['token'],
                'user' => $result['user'],
            ],
        ], 201);
    }

    public function verifyEmail(Request $request, string $id, string $hash): JsonResponse
    {
        $this->auth->verifyEmail($id, $hash);

        return response()->json(['message' => 'Email verified successfully.']);
    }

    public function resendVerification(Request $request): JsonResponse
    {
        $this->auth->resendVerificationNotification($request->user());

        return response()->json(['message' => 'Verification link sent.']);
    }

    public function login(LoginRequest $request): JsonResponse
    {
        $result = $this->auth->login(
            $request->validated(),
            $request->ip(),
            $request->userAgent()
        );

        if (isset($result['two_factor_required']) && $result['two_factor_required']) {
            return response()->json([
                'message' => $result['message'],
                'two_factor_required' => true,
            ], 423);
        }

        return response()->json([
            'data' => [
                'token' => $result['token'],
                'user' => $result['user'],
            ],
        ]);
    }

    public function forgotPassword(ForgotPasswordRequest $request): JsonResponse
    {
        $status = $this->auth->forgotPassword(
            $request->validated(),
            $request->header('X-Client', 'web')
        );

        return response()->json([
            'message' => __($status),
        ]);
    }

    public function resetPassword(ResetPasswordRequest $request): JsonResponse
    {
        $status = $this->auth->resetPassword($request->validated());

        return response()->json([
            'message' => __($status),
        ]);
    }

    public function logout(Request $request): JsonResponse
    {
        $this->auth->logout($request->user());

        return response()->json(['data' => ['message' => 'Logged out']]);
    }

    public function me(Request $request): JsonResponse
    {
        return response()->json(['data' => ['user' => $request->user()]]);
    }

    public function updateProfile(Request $request, UpdateUserProfileInformation $updater): JsonResponse
    {
        $updater->update($request->user(), $request->all());
        return response()->json(['message' => 'Profile updated successfully.']);
    }

    public function updatePassword(Request $request, UpdateUserPassword $updater): JsonResponse
    {
        $updater->update($request->user(), $request->all());
        return response()->json(['message' => 'Password updated successfully.']);
    }

    public function confirmPassword(ConfirmPasswordRequest $request): JsonResponse
    {
        $this->auth->confirmPassword($request->user(), $request->validated('password'));

        return response()->json([
            'message' => 'Password confirmed successfully. Sudo mode enabled.'
        ]);
    }

    public function confirmedPasswordStatus(Request $request): JsonResponse
    {
        $status = $this->auth->passwordConfirmedStatus($request->user());

        return response()->json(['confirmed' => $status]);
    }
}
