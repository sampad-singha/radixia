<?php

namespace App\Application\Programs\Services;

use App\Domain\Meetings\Entities\MeetingWebhookEvent;
use App\Domain\Programs\Entities\CohortSession;
use App\Domain\Programs\Entities\CohortSessionParticipantInterval;
use Illuminate\Support\Facades\DB;

class ProcessMeetingWebhookService
{
    /**
     * @throws \Throwable
     */
    public function handle(MeetingWebhookEvent $event): void
    {
        if ($event->processed) {
            return;
        }

        DB::transaction(function () use ($event) {

            switch ($event->event_type) {

                case 'PARTICIPANT_JOINED':
                    $this->handleParticipantJoined($event);
                    break;

                case 'PARTICIPANT_LEFT':
                    $this->handleParticipantLeft($event);
                    break;

                case 'ROOM_CREATED':
                    // Optional: nothing needed here for intervals
                    break;

                case 'ROOM_DESTROYED':
                    // Optional: nothing here (attendance service will close open intervals)
                    break;
            }

            $event->update(['processed' => true]);
        });
    }

    private function handleParticipantJoined(MeetingWebhookEvent $event): void
    {
        CohortSessionParticipantInterval::create([
            'cohort_session_id' => $this->mapToCohortSessionId($event),
            'participant_id'    => $event->participant_id,
            'user_id'           => $event->user_id,
            'is_moderator'      => $event->is_moderator ?? false,
            'joined_at'         => $event->event_timestamp,
            'left_at'           => null,
            'duration_ms'       => null,
        ]);
    }

    private function handleParticipantLeft(MeetingWebhookEvent $event): void
    {
        $interval = CohortSessionParticipantInterval::where(
            'cohort_session_id',
            $this->mapToCohortSessionId($event)
        )
            ->where('participant_id', $event->participant_id)
            ->whereNull('left_at')
            ->orderByDesc('joined_at')
            ->first();

        if (! $interval) {
            return; // Defensive: LEFT without JOIN
        }

        $interval->left_at = $event->event_timestamp;
        $interval->duration_ms = $interval->left_at - $interval->joined_at;
        $interval->save();
    }

    private function mapToCohortSessionId(MeetingWebhookEvent $event): string
    {
        // IMPORTANT:
        // You must map provider session_id to your internal cohort_session_id.
        // If they are the same, just return:
        $room_id = $event->room_id;
        return CohortSession::where('room_id', $room_id)->value('id');
    }
}