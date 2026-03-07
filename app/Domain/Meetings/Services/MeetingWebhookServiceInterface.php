<?php

namespace App\Domain\Meetings\Services;

interface MeetingWebhookServiceInterface
{
    public function handle(array $payload): void;
}