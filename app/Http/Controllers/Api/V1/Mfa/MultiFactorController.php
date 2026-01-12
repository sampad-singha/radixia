<?php

namespace App\Http\Controllers\Api\V1\Mfa;

use App\Domain\Auth\Exceptions\InvalidTwoFactorCodeException;
use App\Domain\Auth\Repositories\AccessTokenRepositoryInterface;
use App\Domain\Mfa\Services\MfaServiceInterface;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\Auth\ConfirmTwoFactorRequest;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class MultiFactorController extends Controller
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

    public function challenge(Request $request): JsonResponse
    {
        $request->validate(['type' => 'required|string|in:totp,email']);

        // Reuse existing logic by passing the requested MFA type as a provider hint.
        // The service expects this value under the 'mfa_type' key.
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
            'device_name' => 'required|string'
        ]);

        // 1. Verify Code using the service
        $this->mfaService->verifyMfaChallenge(
            $request->user(),
            $request->input('code'),
            $request->input('type')
        );

        // 2. Issue Real Token (Assuming $this->tokens is your AccessTokenRepositoryInterface)
        $token = $this->tokens->create(
            $request->user(),
            $request->input('device_name'),
            $request->ip(),
            $request->userAgent()
        );

        // 3. Revoke Temp Token (Robust check for any MFA pending token)
        $currentToken = $request->user()->currentAccessToken();
        if ($currentToken && str_ends_with($currentToken->name, '-mfa-pending')) {
            $currentToken->delete();
        }

        return response()->json([
            'message' => 'Login successful.',
            'data' => [
                'token' => $token,
                'user' => $request->user()
            ]
        ]);
    }
}
