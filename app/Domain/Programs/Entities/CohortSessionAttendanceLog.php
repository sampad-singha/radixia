<?php

namespace App\Domain\Programs\Entities;

use App\Models\User;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class CohortSessionAttendanceLog extends Model
{
    use HasUuids;

    protected $fillable = [
        'cohort_session_id',
        'user_id',
        'student_active_ms',
        'student_instructor_overlap_ms',
        'ratio_total',
        'ratio_instructor',
        'attended',
    ];

    protected $casts = [
        'student_active_ms' => 'integer',
        'student_instructor_overlap_ms' => 'integer',
        'ratio_total' => 'float',
        'ratio_instructor' => 'float',
        'attended' => 'boolean',
    ];

    public function cohortSession(): BelongsTo
    {
        return $this->belongsTo(CohortSession::class, 'cohort_session_id');
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

}
