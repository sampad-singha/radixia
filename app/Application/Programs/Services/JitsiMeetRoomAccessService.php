<?php

namespace App\Application\Programs\Services;

use App\Domain\Programs\Services\MeetRoomAccessServiceInterface;
use Firebase\JWT\JWT;

class JitsiMeetRoomAccessService implements MeetRoomAccessServiceInterface
{
    public function generateJoinUrl(string $roomId, string $userId, string $displayName, bool $isModerator, int $ttlSeconds, ?string $subject = null): string
    {
        $displayName = trim(strip_tags($displayName));

        $jwt = $this->generateJwt(
            roomId: $roomId,
            userId: $userId,
            displayName: $displayName,
            isModerator: $isModerator,
            ttlSeconds: $ttlSeconds,
        );

        $url = sprintf(
            '%s/%s/%s?jwt=%s',
            rtrim(config('jitsi.base_url'), '/'),
            config('jitsi.app_id'),
            $roomId,
            $jwt
        );

        if ($subject) {
            $url .= '#config.subject=' . rawurlencode($subject);
        }

        return $url;
    }

    private function generateJwt(string $roomId, string $userId, string $displayName, bool $isModerator, ?int $ttlSeconds = null): string
    {
        $now = time();
        $appId = config('jitsi.app_id');

        $payload = [
            'aud' => 'jitsi',
            'iss' => 'chat',
            'sub' => $appId,
            'room' => $roomId,
            'iat' => $now,
            'exp' => $now + ($ttlSeconds ?? 3600),
            'context' => [
                'user' => [
                    'id' => $userId,
                    'name' => $displayName,
                    'affiliation' => $isModerator ? 'owner' : 'member',
                ],
                'features' => [
                    'recording' => true,
                    'livestreaming' => true,
                    'transcription' => true,
                ]
            ],
        ];

        return JWT::encode(
            $payload,
            config('jitsi.secret'),
            'RS256',
            config('jitsi.api_key_id')
        );
    }
}