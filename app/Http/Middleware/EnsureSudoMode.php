<?php

namespace App\Http\Middleware;

use App\Domain\Auth\Services\AuthServiceInterface;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Laravel\Sanctum\PersonalAccessToken;
use Symfony\Component\HttpFoundation\Response;

readonly class EnsureSudoMode
{
    public function __construct(
        private AuthServiceInterface $authService
    ) {}
    /**
     * Handle an incoming request.
     *
     * @param Closure(Request): (Response) $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();
        $result = $user
            ? $this->authService->getSudoStatus($user)
            : [];

        $methods = $result['available_methods'] ?? [];

        /** @var PersonalAccessToken $token */
        $token = $request->user()?->currentAccessToken();

        // If strict API, we expect a token.
        if (! $token instanceof PersonalAccessToken ||
            ! $token->sudo_expires_at ||
            Carbon::parse($token->sudo_expires_at)->isPast()) {

            return response()->json([
                'message' => 'Sudo mode required.',
                'code' => 'SUDO_REQUIRED', // Frontend listens for this code
                'available_methods' => $methods
            ], 423); // 423 Locked
        }

        return $next($request);
    }
}
