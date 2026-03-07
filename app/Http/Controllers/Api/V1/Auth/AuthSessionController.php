<?php

namespace App\Http\Controllers\Api\V1\Auth;

use App\Domain\Auth\Services\AuthServiceInterface;
use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class AuthSessionController extends Controller
{
    public function __construct(
        private readonly AuthServiceInterface $auth
    ) {}

    public function index(Request $request): JsonResponse
    {
        $sessions = $this->auth->listSessions($request->user());
        return response()->json(['data' => $sessions]);
    }

    public function destroy(Request $request, string $tokenId): JsonResponse
    {
        $this->auth->revokeSession($request->user(), $tokenId);
        return response()->json(['message' => 'Session revoked successfully.']);
    }

    public function destroyOthers(Request $request): JsonResponse
    {
        // Protected by 'sudo' middleware in routes
        $this->auth->revokeOtherSessions($request->user());
        return response()->json(['message' => 'All other sessions revoked.']);
    }
}
