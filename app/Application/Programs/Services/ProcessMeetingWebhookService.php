<?php

namespace App\Application\Programs\Services;

use App\Domain\Meetings\Entities\MeetingWebhookEvent;
use App\Domain\Programs\Entities\CohortSession;
use App\Domain\Programs\Entities\CohortSessionParticipantInterval;
use App\Domain\Programs\Services\ProcessMeetingWebhookServiceInterface;
use Illuminate\Support\Facades\DB;
use Throwable;

class ProcessMeetingWebhookService implements ProcessMeetingWebhookServiceInterface
{
    /**
     * @throws Throwable
     */
    public function handle(MeetingWebhookEvent $event): void
    {
        if ($event->processed) {
            return;
        }

        $cohortSessionId = $this->mapToCohortSessionId($event);

        if (!$cohortSessionId) {
            $event->update(['processed' => true]);
            return;
        }

        DB::transaction(function () use ($event, $cohortSessionId) {

            switch ($event->event_type) {

                case 'PARTICIPANT_JOINED':
                    $this->handleParticipantJoined($event, $cohortSessionId);
                    break;

                case 'PARTICIPANT_LEFT':
                    $this->handleParticipantLeft($event, $cohortSessionId);
                    break;

                case 'ROOM_CREATED':
                case 'ROOM_DESTROYED':
                    break;
            }

            $event->update(['processed' => true]);
        });
    }

    private function handleParticipantJoined(
        MeetingWebhookEvent $event,
        string $cohortSessionId
    ): void {

        CohortSessionParticipantInterval::create([
            'cohort_session_id' => $cohortSessionId,
            'participant_id'    => $event->participant_id,
            'user_id'           => $event->user_id,
            'is_moderator'      => $event->is_moderator ?? false,
            'joined_at'         => $event->event_timestamp,
        ]);
    }

    private function handleParticipantLeft(
        MeetingWebhookEvent $event,
        string $cohortSessionId
    ): void {

        $interval = CohortSessionParticipantInterval::where(
            'cohort_session_id',
            $cohortSessionId
        )
            ->where('participant_id', $event->participant_id)
            ->whereNull('left_at')
            ->orderByDesc('joined_at')
            ->first();

        if (! $interval) {
            return;
        }

        $interval->left_at = $event->event_timestamp;
        $interval->duration_ms = $interval->left_at - $interval->joined_at;
        $interval->save();
    }

    private function mapToCohortSessionId(MeetingWebhookEvent $event): ?string
    {
        // IMPORTANT:
        // You must map provider session_id to your internal cohort_session_id.
        // If they are the same, just return:
        $room_id = $event->room_id;
        return CohortSession::where('room_id', $room_id)->value('id');
    }
}
