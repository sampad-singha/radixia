<?php

namespace App\Domain\Programs\Services;

use App\Domain\Meetings\Entities\MeetingWebhookEvent;

interface ProcessMeetingWebhookServiceInterface
{
    public function handle(MeetingWebhookEvent $event): void;
}