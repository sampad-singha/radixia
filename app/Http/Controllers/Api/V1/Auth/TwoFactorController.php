<?php

namespace App\Http\Controllers\Api\V1\Auth;

use App\Domain\Auth\Services\AuthServiceInterface;
use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class TwoFactorController extends Controller
{
    public function __construct(
        private readonly AuthServiceInterface $auth
    ) {}

    public function enable(Request $request): JsonResponse
    {
        $data = $this->auth->enableTwoFactor($request->user());

        return response()->json([
            'message' => 'Two-factor authentication enabled. Please scan the QR code and confirm.',
            'data' => $data
        ]);
    }

    public function regenerateRecoveryCodes(Request $request): JsonResponse
    {
        // Protected by 'sudo' middleware
        $codes = $this->auth->regenerateRecoveryCodes($request->user());

        return response()->json([
            'message' => 'Recovery codes regenerated.',
            'data' => ['recovery_codes' => $codes]
        ]);
    }

    public function confirm(Request $request): JsonResponse
    {
        $request->validate(['code' => 'required|string']);

        $this->auth->confirmTwoFactor($request->user(), $request->code);

        return response()->json([
            'message' => 'Two-factor authentication confirmed and activated.'
        ]);
    }

    public function disable(Request $request): JsonResponse
    {
        $this->auth->disableTwoFactor($request->user());

        return response()->json([
            'message' => 'Two-factor authentication disabled.'
        ]);
    }

    public function recoveryCodes(Request $request): JsonResponse
    {
        $codes = $this->auth->getRecoveryCodes($request->user());

        return response()->json([
            'data' => ['recovery_codes' => $codes]
        ]);
    }
}
