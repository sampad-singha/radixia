<?php

namespace App\Infrastructure\Meetings\Jaas\Services;

use App\Domain\Meetings\Services\MeetRoomAccessServiceInterface;
use Firebase\JWT\JWT;

class JaasMeetRoomAccessService implements MeetRoomAccessServiceInterface
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
                    'moderator' => (bool)$isModerator,
                ],
                'features' => [
                    'recording' => $isModerator,
                    'livestreaming' => $isModerator,
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

    public function getMeetingData(string $roomId, string $userId, string $displayName, bool $isModerator, int $ttlSeconds): array
    {
        return [
            'jwt'    => $this->generateJwt($roomId, $userId, $displayName, $isModerator, $ttlSeconds),
            'room'   => $roomId,
            'appId'  => config('jitsi.app_id'),
            'is_moderator' => $isModerator,
        ];
    }
}