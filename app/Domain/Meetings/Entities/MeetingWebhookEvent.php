<?php

namespace App\Domain\Meetings\Entities;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property string $source
 * @property string $event_type
 * @property string|null $room_id
 * @property string|null $session_id
 * @property string|null $participant_id
 * @property string|null $user_id
 * @property string|null $participant_name
 * @property bool|null $is_moderator
 * @property int|null $event_timestamp
 * @property string|null $idempotency_key
 * @property array|null $raw_payload
 * @property bool $processed
 */

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
        'user_id',
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
