<?php

namespace App\Jobs;

use App\Domain\Meetings\Services\MeetingWebhookServiceInterface;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Throwable;

class ProcessMeetingWebhook implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $tries = 3;      // max retry attempts
    public array $backoff = [10, 30, 60];   // seconds between retries

    /**
     * Create a new job instance.
     */
    public function __construct(
        public array $payload
    ) {}

    /**
     * Execute the job.
     */
    public function handle(MeetingWebhookServiceInterface $webhookService): void
    {
        $webhookService->handle($this->payload);
    }

    public function failed(Throwable $exception): void
    {
        $roomId = $this->payload['room_id'] ?? null;
        if (isset($this->payload['room']['id'])) {
            $roomId = $this->payload['room']['id'];
        }
        Log::critical('Webhook job failed', [
            'idempotency_key' => $this->payload['idempotency_key'] ?? null,
            'event_type' => $this->payload['event_type'] ?? null,
            'room_id' => $roomId,
            'error' => $exception->getMessage(),
        ]);
    }
}
