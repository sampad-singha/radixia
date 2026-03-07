<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class VerifyJaasSignature
{
    /**
     * Handle an incoming request.
     *
     * @param Closure(Request): (Response) $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $header = $request->header('X-Jaas-Signature');

        if (!$header) {
            Log::warning('Webhook rejected: signature header missing');
            abort(401, 'Signature missing');
        }

        if (
            !preg_match('/t=(\d+)/', $header, $tMatch) ||
            !preg_match('/v1=([^,]+)/', $header, $sMatch)
        ) {
            Log::warning('Webhook rejected: malformed signature header', [
                'header' => $header,
            ]);
            abort(401, 'Invalid signature header');
        }

        $timestamp = $tMatch[1];
        $signature = trim($sMatch[1]);

        if (!ctype_digit($timestamp)) {
            Log::warning('Webhook rejected: invalid timestamp', [
                'timestamp' => $timestamp,
            ]);
            abort(401, 'Invalid timestamp');
        }

        if ($signature === '') {
            Log::warning('Webhook rejected: empty signature');
            abort(401, 'Invalid signature');
        }

        $diff = time() - (int) $timestamp;

        if (abs($diff) > 300) {
            Log::warning('Webhook rejected: timestamp outside tolerance', [
                'difference_seconds' => $diff,
            ]);
            abort(401, 'Request expired');
        }

        $secret = config('jitsi.webhook_secret');

        if (!$secret) {
            Log::critical('Webhook rejected: webhook secret missing');
            abort(500, 'Webhook configuration error');
        }

        $signedPayload = $timestamp . '.' . $request->getContent();

        $expected = base64_encode(
            hash_hmac('sha256', $signedPayload, $secret, true)
        );

        if (!hash_equals($expected, $signature)) {
            Log::warning('Webhook rejected: HMAC mismatch');
            abort(401, 'Invalid signature');
        }

        return $next($request);
    }
}
