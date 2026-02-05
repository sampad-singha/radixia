<?php

namespace App\Application\Programs\Services;

use App\Domain\Programs\Entities\CohortSession;
use App\Domain\Programs\Enums\SessionStatus;
use App\Domain\Programs\Exceptions\CohortNotFoundException;
use App\Domain\Programs\Exceptions\CohortSessionNotFoundException;
use App\Domain\Programs\Exceptions\ImmutableFieldException;
use App\Domain\Programs\Exceptions\InvalidSessionTimeException;
use App\Domain\Programs\Exceptions\MeetingAccessRestrictedException;
use App\Domain\Programs\Exceptions\RestrictedStatusException;
use App\Domain\Programs\Exceptions\SessionOutsideCohortRangeException;
use App\Domain\Programs\Repositories\CohortRepositoryInterface;
use App\Domain\Programs\Repositories\CohortSessionRepositoryInterface;
use App\Domain\Programs\Services\CohortSessionServiceInterface;
use App\Domain\Programs\Services\MeetRoomAccessServiceInterface;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Support\Str;

readonly class CohortSessionService implements CohortSessionServiceInterface
{
    public function __construct(
        private CohortSessionRepositoryInterface $sessionRepo,
        private CohortRepositoryInterface        $cohortRepo,
        private MeetRoomAccessServiceInterface   $meetService
    )
    {
    }

    /**
     * @throws CohortSessionNotFoundException
     */
    public function getById(string $id): CohortSession
    {
        $session = $this->sessionRepo->findById($id);
        if (!$session) {
            throw new CohortSessionNotFoundException("Cohort session not found.");
        }
        return $session;
    }

    /**
     * @throws CohortSessionNotFoundException
     */
    public function findByIdWithTrashed(string $id): CohortSession
    {
        $session =  $this->sessionRepo->findByIdWithTrashed($id);
        if (!$session) {
            throw new CohortSessionNotFoundException("Cohort session not found.");
        }
        return $session;
    }

    /**
     * @throws CohortNotFoundException
     * @throws SessionOutsideCohortRangeException
     */
    public function scheduleSession(array $data): CohortSession
    {
        $cohort = $this->cohortRepo->findById($data['cohort_id']);

        if (! $cohort) {
            throw new CohortNotFoundException();
        }

        // Parse session datetimes
        $sessionStartDate = Carbon::parse($data['starts_at'])->toDateString();
        $sessionEndDate   = Carbon::parse($data['ends_at'])->toDateString();

        // Cohort dates (already Carbon due to cast)
        $cohortStartDate = $cohort->start_date->toDateString();
        $cohortEndDate   = $cohort->end_date->toDateString();

        if (
            $sessionStartDate < $cohortStartDate ||
            $sessionEndDate > $cohortEndDate
        ) {
            throw new SessionOutsideCohortRangeException(
                'Session date must be within cohort date range.'
            );
        }

        $data['room_id'] = 'room-' . Str::uuid();
        $data['status'] = SessionStatus::SCHEDULED;

        return $this->sessionRepo->create($data);
    }

    /**
     * @throws RestrictedStatusException
     * @throws InvalidSessionTimeException
     * @throws ImmutableFieldException
     */
    public function updateSession(CohortSession $session, array $data): CohortSession
    {
        $immutableFields = ['cohort_id', 'room_id', 'lesson_id', 'recording_url', 'status'];

        if (array_intersect($immutableFields, array_keys($data))) {
            throw new ImmutableFieldException('One or more immutable fields were provided.');
        }

        if ($session->status === SessionStatus::COMPLETED) {
            throw new RestrictedStatusException(SessionStatus::COMPLETED->value);
        }

        $startsAt = isset($data['starts_at']) ? Carbon::parse($data['starts_at']) : $session->starts_at;

        $endsAt = isset($data['ends_at']) ? Carbon::parse($data['ends_at']) : $session->ends_at;

        if ($startsAt->gte($endsAt)) {
            throw new InvalidSessionTimeException('Session start time must be before end time.');
        }

        if ($session->status === SessionStatus::SCHEDULED && $startsAt->isPast()) {
            throw new InvalidSessionTimeException('Scheduled sessions cannot be moved to the past.');
        }

        $resolvedStatus = $this->resolveStatus($session);

        if ($resolvedStatus === SessionStatus::LIVE && $endsAt->isPast()) {
            throw new InvalidSessionTimeException('Live sessions cannot end in the past.');
        }

        return $this->sessionRepo->update($session, $data);
    }

    /**
     * @throws RestrictedStatusException
     */
    public function deleteSession(CohortSession $session): void
    {
        if ($session->status === SessionStatus::COMPLETED) {
            throw new RestrictedStatusException($session->status->value);
        }

        if ($this->resolveStatus($session) === SessionStatus::LIVE) {
            throw new RestrictedStatusException(SessionStatus::LIVE->value);
        }

        $this->sessionRepo->delete($session);
    }

    public function restoreSession(CohortSession $session): CohortSession
    {
        $this->sessionRepo->restore($session);
        return $session->fresh();
    }

    /**
     * @throws RestrictedStatusException
     */
    public function markSessionCompleted(CohortSession $session): CohortSession
    {
        if ($session->status === SessionStatus::COMPLETED) {
            throw new RestrictedStatusException(
                SessionStatus::COMPLETED->value
            );
        }

        if ($session->status === SessionStatus::CANCELLED) {
            throw new RestrictedStatusException(
                SessionStatus::CANCELLED->value
            );
        }

        if (Carbon::now()->lt($session->starts_at)) {
            throw new RestrictedStatusException(
                'scheduled'
            );
        }

        return $this->sessionRepo->update($session, [
            'status' => SessionStatus::COMPLETED,
        ]);
    }

    /**
     * @throws RestrictedStatusException
     */
    public function cancelSession(CohortSession $session, ?string $reason = null): CohortSession
    {
        // Completed sessions cannot be cancelled
        if ($session->status === SessionStatus::COMPLETED) {
            throw new RestrictedStatusException(
                SessionStatus::COMPLETED->value
            );
        }

        // Already cancelled → no-op or exception (choose strict)
        if ($session->status === SessionStatus::CANCELLED) {
            throw new RestrictedStatusException(
                SessionStatus::CANCELLED->value
            );
        }

        $payload = [
            'status' => SessionStatus::CANCELLED,
        ];

        // Optional: persist cancellation reason if column exists
        if ($reason !== null) {
            $payload['cancellation_reason'] = $reason;
        }

        return $this->sessionRepo->update($session, $payload);
    }


    /**
     * @throws MeetingAccessRestrictedException
     */
    public function canJoin(CohortSession $session, User $user): bool
    {
        if ($session->isCancelled()) {
            throw new MeetingAccessRestrictedException('Session has been cancelled.');
        }

        $status = $this->resolveStatus($session);

        if (!in_array($status, [SessionStatus::LIVE, SessionStatus::SCHEDULED,], true)) {
            throw new MeetingAccessRestrictedException('Session is not live or scheduled.');
        }

        $joinWindowStart = $session->starts_at->copy()->subMinutes(15);

        if (now()->lt($joinWindowStart)) {
            throw new MeetingAccessRestrictedException('Joining is not allowed yet.');
        }

        if ($user->isAdmin()) {
            return true;
        }

        if ($user->isInstructor()) {
            return $user->id === $session->cohort->assigned_instructor_id;
        }

        if ($this->cohortRepo->isUserEnrolled($session->cohort_id, $user->id)) {
            return true;
        } else {
            throw new MeetingAccessRestrictedException('User is not enrolled in the cohort.');
        }
    }

    /**
     * @throws MeetingAccessRestrictedException
     */
    public function getMeetingDetails(CohortSession $session, User $user): array
    {
        if (!$this->canJoin($session, $user)) {
            throw new MeetingAccessRestrictedException();
        }

        $isModerator = $this->isModerator($session, $user);
        $ttlSeconds = $this->calculateJoinTtlSeconds($session);

        // Call the NEW array-based method you added
        $data = $this->meetService->getMeetingData(
            roomId: $session->room_id,
            userId: (string)$user->id,
            displayName: $user->name,
            isModerator: $isModerator,
            ttlSeconds: $ttlSeconds
        );

        // Add the subject here so JS can use it easily
        $data['subject'] = sprintf('%s – %s', $session->cohort->name, $session->lesson->title);

        return $data;
    }

    public function resolveStatus(CohortSession $session): SessionStatus
    {
        if ($session->status === SessionStatus::CANCELLED) {
            return SessionStatus::CANCELLED;
        }

        if ($session->status === SessionStatus::COMPLETED) {
            return SessionStatus::COMPLETED;
        }

        $now = Carbon::now();

        if ($now->lt($session->starts_at)) {
            return SessionStatus::SCHEDULED;
        }

        if ($now->between($session->starts_at, $session->ends_at)) {
            return SessionStatus::LIVE;
        }

        return SessionStatus::COMPLETED;
    }

    private function isModerator(CohortSession $session, User $user): bool
    {
        if ($user->isAdmin()) {
            return true;
        }

        if ($user->isInstructor()) {
            return $user->id === $session->cohort->assigned_instructor_id;
        }

        return false;
    }

    private function calculateJoinTtlSeconds(CohortSession $session): int
    {
        $now = Carbon::now();

        // Session already ended → minimal TTL (safety)
        if ($now->gte($session->ends_at)) {
            return 300; // 5 minutes
        }

        $secondsUntilEnd = $now->diffInSeconds($session->ends_at);

        // Add 30 minutes buffer
        return $secondsUntilEnd + (30 * 60);
    }

}
