<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Laravel\Sanctum\PersonalAccessToken;
use Symfony\Component\HttpFoundation\Response;

class EnsureSudoMode
{
    /**
     * Handle an incoming request.
     *
     * @param Closure(Request): (Response) $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        /** @var PersonalAccessToken $token */
        $token = $request->user()?->currentAccessToken();

        // If strict API, we expect a token.
        if (! $token instanceof PersonalAccessToken ||
            ! $token->sudo_expires_at ||
            Carbon::parse($token->sudo_expires_at)->isPast()) {

            return response()->json([
                'message' => 'Password confirmation required.',
                'code' => 'SUDO_REQUIRED' // Frontend listens for this code
            ], 423); // 423 Locked
        }

        return $next($request);
    }
}
