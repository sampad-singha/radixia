<?php

namespace App\Http\Controllers\Api\V1\Auth;

use App\Actions\Fortify\UpdateUserProfileInformation;
use App\Domain\Auth\Exceptions\PasswordAlreadySetException;
use App\Domain\Auth\Services\AuthServiceInterface;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\Auth\ChangePasswordRequest;
use App\Http\Requests\Api\V1\Auth\ConfirmSudoRequest;
use App\Http\Requests\Api\V1\Auth\ForgotPasswordRequest;
use App\Http\Requests\Api\V1\Auth\GetSudoUserRequest;
use App\Http\Requests\Api\V1\Auth\LoginRequest;
use App\Http\Requests\Api\V1\Auth\RegisterRequest;
use App\Http\Requests\Api\V1\Auth\ResetPasswordRequest;
use App\Http\Requests\Api\V1\Auth\SetPasswordRequest;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
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

    public function verifyEmail(Request $request, string $id, string $hash): RedirectResponse
    {
        $this->auth->verifyEmail($id, $hash);

        $frontendUrl = $request->query('client_url', config('app.frontend_url'));

        return redirect()->to($frontendUrl . '/email-verified?verified=1');
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

        // --- NEW: MFA Handling ---
        if (isset($result['mfa_required']) && $result['mfa_required']) {
            return response()->json([
                'message' => $result['message'],
                'mfa_required' => true,
                'available_methods' => $result['available_methods'] ?? [],
                'challenge_sent' => $result['challenge_sent'] ?? false, // Frontend needs this to know if it should expect a code immediately
                'token' => $result['token'],
            ], 423); // 423 Locked
        }

        // --- Standard Login Success ---
        $response = [
            'data' => [
                'token' => $result['token'],
                'user' => $result['user'],
            ],
        ];

        return response()->json($response);
    }

    public function forgotPassword(ForgotPasswordRequest $request): JsonResponse
    {
        $status = $this->auth->forgotPassword(
            $request->validated(),
            $request->header('Origin')
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

    public function updateAccount(Request $request, UpdateUserProfileInformation $updater): JsonResponse
    {
        $updater->update($request->user(), $request->all());
        return response()->json(['message' => 'Account information updated successfully.']);
    }

    public function confirmSudo(ConfirmSudoRequest $request): JsonResponse
    {
        $type = $request->validated('type');
        $value = $request->validated('value');

        $this->auth->confirmSudoMode($request->user(), $type, $value);

        return response()->json([
            'message' => 'Sudo mode enabled.'
        ]);
    }

    public function getSudoUser(GetSudoUserRequest $request): JsonResponse
    {
        // Use the new service method
        $status = $this->auth->getSudoStatus($request->user());

        return response()->json($status);
    }

    public function changePassword(ChangePasswordRequest $request): JsonResponse
    {
        $this->auth->changePassword(
            $request->user(),
            $request->validated('current_password'),
            $request->validated('password')
        );

        return response()->json([
            'message' => 'Password changed successfully. All sessions have been logged out.',
        ]);
    }

    /**
     * @throws PasswordAlreadySetException
     */
    public function setPassword(SetPasswordRequest $request): JsonResponse
    {
        $this->auth->setPassword($request->user(), $request->validated('password'));

        return response()->json(['message' => 'Password set successfully.']);
    }
}
