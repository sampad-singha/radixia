<?php

namespace App\Infrastructure\Meetings\Jaas\Services;

use App\Application\Programs\Services\ProcessMeetingWebhookService;
use App\Domain\Meetings\Entities\MeetingWebhookEvent;
use App\Domain\Meetings\Services\MeetingWebhookServiceInterface;
use Illuminate\Database\QueryException;
use Throwable;

class JaasWebhookService implements MeetingWebhookServiceInterface
{
    public function __construct(
        public ProcessMeetingWebhookService $processWebhook
    )
    {
        // Inject any dependencies if needed
    }

    /**
     * @throws Throwable
     */
    public function handle(array $payload): void
    {
        $idempotencyKey = $payload['idempotencyKey'] ?? null;

        try {
            $event = MeetingWebhookEvent::create([
                'source' => 'jaas',
                'event_type' => $payload['eventType'] ?? 'unknown',
                'room_id' => $this->extractRoomName($payload['fqn'] ?? null),
                'session_id' => $payload['sessionId'] ?? null,
                'participant_id' => $payload['data']['participantId'] ?? null,
                'user_id' => $payload['data']['id'] ?? null,
                'participant_name' => $payload['data']['name'] ?? null,
                'is_moderator' => $payload['data']['moderator'] ?? null,
                'event_timestamp' => $payload['timestamp'] ?? now()->valueOf(),
                'idempotency_key' => $idempotencyKey,
                'raw_payload' => $payload,
                'processed' => false,
            ]);
        } catch (QueryException $e) {

            $event = MeetingWebhookEvent::where('source', 'jaas')
                ->where('idempotency_key', $idempotencyKey)
                ->first();

            if (!$event) {
                throw $e;
            }
        }

        if ($event->processed) {
            return;
        }

        $this->processWebhook->handle($event);
    }

    private function extractRoomName(?string $fqn): ?string
    {
        if (! $fqn) {
            return null;
        }

        // Example:
        // vpaas-magic-cookie-xxx/room-6d3c3ec7-...

        return substr($fqn, strrpos($fqn, '/') + 1);
    }
}
