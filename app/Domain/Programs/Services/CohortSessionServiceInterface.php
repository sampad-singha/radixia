<?php

namespace App\Domain\Programs\Services;

use App\Domain\Programs\Entities\CohortSession;
use App\Domain\Programs\Enums\SessionStatus;
use App\Models\User;

interface CohortSessionServiceInterface
{
    public function scheduleSession(array $data): CohortSession;
    public function updateSession(CohortSession $session, array $data): CohortSession;
    public function deleteSession(CohortSession $session): void;

    public function restoreSession(CohortSession $session): CohortSession;
    public function getById(string $id): CohortSession;

    // Lifecycle
    public function markSessionCompleted(CohortSession $session): CohortSession;
    public function cancelSession(CohortSession $session, ?string $reason = null): CohortSession;

    // Access
    public function canJoin(CohortSession $session, User $user): bool;
    public function getJoinLink(CohortSession $session, User $user): string;

    // Post-class
//    public function attachRecording(CohortSession $session, string $videoId): CohortSession;

    // Status resolution
    public function resolveStatus(CohortSession $session): SessionStatus;
}