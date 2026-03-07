<?php

namespace App\Domain\Programs\Entities;

use App\Models\User;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * @property string $id
 * @property string cohort_session_id
 * @property string participant_id
 * @property string user_id
 * @property bool is_moderator
 * @property int joined_at
 * @property int|null left_at
 * @property int|null duration_ms
 * @property CohortSession cohortSession
 * @property User user
 **/
class CohortSessionParticipantInterval extends Model
{
    use HasUuids;

    protected $fillable = [
        'cohort_session_id',
        'participant_id',
        'user_id',
        'is_moderator',
        'joined_at',
        'left_at',
        'duration_ms',
    ];

    protected $casts = [
        'is_moderator' => 'boolean',
        'joined_at'    => 'integer',
        'left_at'      => 'integer',
        'duration_ms'  => 'integer',
    ];

    public function cohortSession(): BelongsTo
    {
        return $this->belongsTo(CohortSession::class, 'cohort_session_id');
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function isOpen(): bool
    {
        return is_null($this->left_at);
    }
}
