<?php

namespace App\Http\Controllers\Api\V1\Auth;

use App\Domain\Mfa\Services\MfaServiceInterface;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\Auth\ConfirmTwoFactorRequest;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class TwoFactorController extends Controller
{
    public function __construct(
        private readonly MfaServiceInterface $mfaService
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
        $request->validate(['type' => 'required|string|in:totp,email']);

        $this->mfaService->disable($request->user(), $request->type);

        return response()->json([
            'message' => 'Two-factor authentication disabled.'
        ]);
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
}
