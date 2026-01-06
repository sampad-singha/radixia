<?php

namespace App\Http\Controllers\Api\V1\Auth;

use App\Application\Auth\Services\SocialAuthService;
use App\Domain\Auth\Exceptions\SocialProviderException;
use App\Domain\Auth\Exceptions\SocialEmailRequiredException;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\Auth\SocialLoginRequest;
use Illuminate\Http\JsonResponse;

class SocialAuthController extends Controller
{
    public function __construct(private readonly SocialAuthService $service) {}

    /**
     * @throws SocialEmailRequiredException
     * @throws SocialProviderException
     */
    public function callback(SocialLoginRequest $request, string $provider): JsonResponse
    {
        $result = $this->service->handleProviderCallback(
            $provider,
            $request->validated('code'),
            $request->validated('redirect_uri'),
            $request->validated('email')
        );

        return response()->json([
            'data' => [
                'token' => $result['token'],
                'user' => $result['user'],
            ]
        ]);
    }
}
