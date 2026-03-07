<?php

namespace App\Http\Controllers\Api\V1\Auth;

use App\Domain\Auth\Services\SocialAuthServiceInterface;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\Auth\SocialLoginRequest;
use Illuminate\Http\JsonResponse;

class SocialAuthController extends Controller
{
    public function __construct(
        private readonly SocialAuthServiceInterface $service
    ) {}

    public function callback(SocialLoginRequest $request, string $provider): JsonResponse
    {
        // 1. Determine the base Frontend URL from the Origin header
        $origin = $request->header('Origin');
        $allowedOrigins = config('auth.allowed_origins', []);
        $baseUrl = ($origin && in_array($origin, $allowedOrigins))
            ? $origin
            : config('app.frontend_url');

        // 2. Construct the exact Redirect URI expected by the Provider
        $redirectUrl = "{$baseUrl}/auth/{$provider}/callback";

        $result = $this->service->handleProviderCallback(
            $provider,
            $redirectUrl
        );

        // --- NEW: MFA Handling (same pattern as AuthController::login) ---
        if (isset($result['mfa_required']) && $result['mfa_required']) {
            return response()->json([
                'message' => $result['message'],
                'mfa_required' => true,
                'available_methods' => $result['available_methods'] ?? [],
                'challenge_sent' => $result['challenge_sent'] ?? false,
                'token' => $result['token'],
            ], 423); // 423 Locked
        }

        // --- Standard Success ---
        return response()->json([
            'data' => [
                'token' => $result['token'],
                'user' => $result['user'],
            ]
        ]);
    }
}
