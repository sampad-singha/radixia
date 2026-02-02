<?php

namespace App\Domain\Programs\Services;

interface MeetRoomAccessServiceInterface
{
    public function generateJoinUrl(
        string $roomId,
        string $userId,
        string $displayName,
        bool $isModerator,
        int $ttlSeconds,
        ?string $subject = null
    ): string;

    public function getMeetingData(string $roomId, string $userId, string $displayName, bool $isModerator, int $ttlSeconds): array;
}