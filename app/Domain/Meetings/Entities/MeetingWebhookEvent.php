<?php

namespace App\Domain\Meetings\Entities;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

class MeetingWebhookEvent extends Model
{
    use HasUuids;

    protected $table = 'meeting_webhook_events';

    protected $fillable = [
        'source',
        'event_type',
        'room_id',
        'session_id',
        'participant_id',
        'participant_name',
        'is_moderator',
        'event_timestamp',
        'idempotency_key',
        'raw_payload',
        'processed',
    ];

    protected $casts = [
        'raw_payload' => 'array',
        'is_moderator' => 'boolean',
        'processed' => 'boolean',
    ];
}
