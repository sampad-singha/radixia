<?php

namespace App\Infrastructure\Meetings\Jaas\Services;

use App\Domain\Meetings\Services\MeetingWebhookServiceInterface;
use Illuminate\Support\Facades\DB;

class JaasWebhookService implements MeetingWebhookServiceInterface
{
    public function handle(array $payload): void
    {
        // 1. Check Idempotency to prevent duplicate processing
        $idempotencyKey = $payload['idempotency_key'] ?? null;
        if ($this->isAlreadyProcessed($idempotencyKey)) {
            return;
        }

        // 2. Log the raw event for audit and future re-processing
        DB::table('meeting_attendance_logs')->insert([
            'id' => \Illuminate\Support\Str::uuid(),
            'event_type' => $payload['eventType'] ?? 'unknown',
            'room_name' => $payload['roomName'] ?? 'unknown',
            'event_timestamp' => $payload['timestamp'] ?? now()->getTimestamp(),
            'idempotency_key' => $idempotencyKey,
            'raw_payload' => json_encode($payload),
            'processed' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        // 3. Dispatch Background Job for insights (Duration/Attendance)
        // This keeps the webhook response time extremely fast.
        // ProcessMeetingInsights::dispatch($idempotencyKey);
    }

    private function isAlreadyProcessed(?string $key): bool
    {
        if (!$key) return false;
        return DB::table('meeting_attendance_logs')->where('idempotency_key', $key)->exists();
    }
}