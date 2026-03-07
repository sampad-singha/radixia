<?php

namespace App\Domain\Meetings\Services;

interface MeetingCommandServiceInterface
{
    public function destroyByRoom(string $roomName): void;
}
