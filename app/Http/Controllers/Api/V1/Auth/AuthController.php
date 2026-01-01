<?php

namespace App\Http\Controllers\Api\V1\Auth;

use App\Actions\Fortify\UpdateUserPassword;
use App\Actions\Fortify\UpdateUserProfileInformation;
use App\Domain\Auth\Services\AuthServiceInterface;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\Auth\ForgotPasswordRequest;
use App\Http\Requests\Api\V1\Auth\LoginRequest;
use App\Http\Requests\Api\V1\Auth\RegisterRequest;
use App\Http\Requests\Api\V1\Auth\ResetPasswordRequest;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function __construct(private readonly AuthServiceInterface $auth) {}

    public function register(RegisterRequest $request)
    {
        $result = $this->auth->register($request->validated());

        return response()->json([
            'data' => [
                'token' => $result['token'],
                'user' => $result['user'],
            ],
        ], 201);
    }

    public function verifyEmail(Request $request, $id, $hash)
    {
        $this->auth->verifyEmail($id, $hash);

        return response()->json(['message' => 'Email verified successfully.']);
    }

    public function resendVerification(Request $request)
    {
        $this->auth->resendVerificationNotification($request->user());

        return response()->json(['message' => 'Verification link sent.']);
    }

    public function login(LoginRequest $request)
    {
        $result = $this->auth->login($request->validated());

        return response()->json([
            'data' => [
                'token' => $result['token'],
                'user' => $result['user'],
            ],
        ]);
    }

    public function forgotPassword(ForgotPasswordRequest $request)
    {
        $status = $this->auth->forgotPassword($request->validated());

        return response()->json([
            'message' => $status,
        ]);
    }

    public function resetPassword(ResetPasswordRequest $request)
    {
        $status = $this->auth->resetPassword($request->validated());

        return response()->json([
            'message' => $status,
        ]);
    }

    public function logout(Request $request)
    {
        $this->auth->logout($request->user());

        return response()->json(['data' => ['message' => 'Logged out']]);
    }

    public function me(Request $request)
    {
        return response()->json(['data' => ['user' => $request->user()]]);
    }

    public function updateProfile(Request $request, UpdateUserProfileInformation $updater)
    {
        $updater->update($request->user(), $request->all());
        return response()->json(['message' => 'Profile updated successfully.']);
    }

    public function updatePassword(Request $request, UpdateUserPassword $updater)
    {
        $updater->update($request->user(), $request->all());
        return response()->json(['message' => 'Password updated successfully.']);
    }
}
