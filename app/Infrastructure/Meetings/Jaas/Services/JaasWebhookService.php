<?php

namespace App\Infrastructure\Meetings\Jaas\Services;

use App\Domain\Meetings\Entities\MeetingWebhookEvent;
use App\Domain\Meetings\Services\MeetingWebhookServiceInterface;
use Illuminate\Support\Facades\DB;

class JaasWebhookService implements MeetingWebhookServiceInterface
{
    public function handle(array $payload): void
    {
        $idempotencyKey = $payload['idempotencyKey'] ?? null;

        if ($this->alreadyProcessed($idempotencyKey)) {
            return;
        }

        MeetingWebhookEvent::create([
            'source' => 'jaas',
            'event_type' => $payload['eventType'] ?? 'unknown',
            'room_id' => $payload['fqn'] ?? null,
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
    }

    private function alreadyProcessed(?string $key): bool
    {
        if (!$key) {
            return false;
        }

        return MeetingWebhookEvent::query()
            ->where('source', 'jaas')
            ->where('idempotency_key', $key)
            ->exists();
    }
}
