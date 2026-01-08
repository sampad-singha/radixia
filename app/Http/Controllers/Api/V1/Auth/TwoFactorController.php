<?php

namespace App\Http\Controllers\Api\V1\Auth;

use App\Domain\Auth\Exceptions\InvalidTwoFactorCodeException;
use App\Domain\Auth\Repositories\AccessTokenRepositoryInterface;
use App\Domain\Mfa\Services\MfaServiceInterface;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\Auth\ConfirmTwoFactorRequest;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class TwoFactorController extends Controller
{
    public function __construct(
        private readonly MfaServiceInterface $mfaService,
        private readonly AccessTokenRepositoryInterface $tokens, // Need this to issue
    ) {}

    public function enable(Request $request): JsonResponse
    {
        $request->validate(['type' => 'required|string|in:totp,email']);

        $data = $this->mfaService->enable($request->user(), $request->type);

        return response()->json([
            'message' => 'Setup initiated. Please confirm to activate.',
            'type' => $request->type,
            'data' => $data
        ]);
    }

    public function confirm(ConfirmTwoFactorRequest $request): JsonResponse
    {
        $this->mfaService->confirm(
            $request->user(),
            $request->validated('type'),
            $request->validated('code')
        );

        return response()->json([
            'message' => 'Two-factor authentication confirmed and activated.'
        ]);
    }

    public function disable(Request $request): JsonResponse
    {
        // Validate that 'type' is a string OR null
        $type = $request->query('type');

        $this->mfaService->disable($request->user(), $type);

        $message = $type
            ? "{$type} authentication disabled."
            : "Two-factor authentication disabled for all methods.";

        return response()->json(['message' => $message]);
    }

    public function regenerateRecoveryCodes(Request $request): JsonResponse
    {
        // Usually TOTP specific, but service handles logic
        $codes = $this->mfaService->regenerateRecoveryCodes($request->user());

        return response()->json([
            'message' => 'Recovery codes regenerated.',
            'data' => ['recovery_codes' => $codes]
        ]);
    }

    public function recoveryCodes(Request $request): JsonResponse
    {
        $codes = $this->mfaService->getRecoveryCodes($request->user());

        return response()->json([
            'data' => ['recovery_codes' => $codes]
        ]);
    }

    /**
     * @throws InvalidTwoFactorCodeException
     */
    public function challenge(Request $request): JsonResponse
    {
        $request->validate(['type' => 'required|string|in:totp,email']);

        // Reuse existing logic.
        // We pass 'mfa_type' in the data array to force the specific provider logic.
        $result = $this->mfaService->checkMfaRequirement($request->user(), [
            'mfa_type' => $request->type
        ]);

        return response()->json([
            'message' => $result['message'],
            'challenge_sent' => $result['challenge_sent'],
        ]);
    }

    /**
     * @throws InvalidTwoFactorCodeException
     */
    public function verifyLogin(Request $request): JsonResponse
    {
        $request->validate([
            'code' => 'required|string',
            'type' => 'required|string|in:totp,email',
            'device_name' => 'required|string' // Needed for new token
        ]);

        // 1. Verify Code using the new service method
        $this->mfaService->verifyMfaChallenge(
            $request->user(),
            $request->code,
            $request->type
        );

        // 2. Issue Real Token
        $token = $this->tokens->create(
            $request->user(),
            $request->device_name,
            $request->ip(),
            $request->userAgent()
        );

        // 3. Revoke Temp Token (if applicable)
        if ($request->user()->currentAccessToken()->name === 'login-mfa-pending') {
            $request->user()->currentAccessToken()->delete();
        }

        return response()->json([
            'message' => 'Login successful.',
            'data' => [
                'token' => $token, // Plain text token from repo
                'user' => $request->user()
            ]
        ]);
    }
}
