<?php

namespace App\Infrastructure\Meetings\Jaas\Services;

use App\Domain\Meetings\Services\MeetingCommandServiceInterface;
use Firebase\JWT\JWT;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Http;

class JaasCommandService implements MeetingCommandServiceInterface
{
    /**
     * @throws RequestException
     * @throws ConnectionException
     */
    public function destroyByRoom(string $roomName): void
    {
        $conferenceFullName = $this->buildConferenceFullName($roomName);

        Http::withToken($this->generateAdminJwt())
            ->timeout(10)
            ->post(
                config('jitsi.command_url'),
                [
                    'action' => 'DESTROY',
                    'payload' => [
                        'conferenceFullName' => $conferenceFullName,
                    ],
                ]
            )
            ->throw();
    }

    private function buildConferenceFullName(string $roomName): string
    {
        return sprintf(
            '%s@conference.%s.8x8.vc',
            $roomName,
            config('jitsi.app_id')
        );
    }

    private function generateAdminJwt(): string
    {
        $now = time();

        $payload = [
            'aud'   => 'jitsi',
            'iss'   => 'chat',
            'sub'   => config('jitsi.app_id'),
            'iat'   => $now,
            'nbf'   => $now,
            'exp'   => $now + 60,
            'admin' => true,
        ];

        return JWT::encode(
            $payload,
            config('jitsi.secret'),
            'RS256',
            config('jitsi.api_key_id')
        );
    }
}
