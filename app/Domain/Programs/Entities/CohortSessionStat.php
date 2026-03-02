<?php

namespace App\Domain\Programs\Entities;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * @property string $id
 * @property string cohort_session_id
 * @property int room_created_at
 * @property int room_destroyed_at
 * @property int total_meeting_ms
 * @property int instructor_active_ms
 * @property bool finalized
 * @property CohortSession cohortSession
 **/
class CohortSessionStat extends Model
{
    use HasUuids;

    protected $fillable = [
        'cohort_session_id',
        'room_created_at',
        'room_destroyed_at',
        'total_meeting_ms',
        'instructor_active_ms',
        'finalized',
    ];

    protected $casts = [
        'room_created_at'  => 'integer',
        'room_destroyed_at'=> 'integer',
        'total_meeting_ms' => 'integer',
        'instructor_active_ms'=> 'integer',
        'finalized'        => 'boolean',
    ];

    public function cohortSession(): BelongsTo
    {
        return $this->belongsTo(CohortSession::class, 'cohort_session_id');
    }
}
