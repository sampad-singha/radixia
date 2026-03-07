<?php

namespace App\Domain\Programs\Entities;

use App\Domain\Programs\Enums\SessionStatus;
use Database\Factories\CohortSessionFactory;
use DateTimeInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * @property string $id
 * @property string $cohort_id
 * @property string $lesson_id
 * @property DateTimeInterface $starts_at
 * @property DateTimeInterface $ends_at
 * @property string $room_id
 * @property string $recording_url
 * @property SessionStatus $status
 * @property Cohort $cohort
 * @property Lesson $lesson
 */
class CohortSession extends Model
{
    use HasFactory, HasUuids, SoftDeletes;

    protected $fillable = [
        'cohort_id',
        'lesson_id',
        'starts_at',
        'ends_at',
        'room_id',
        'recording_url',
        'status'
    ];

    protected $casts = [
        'starts_at' => 'datetime',
        'ends_at' => 'datetime',
        'status' => SessionStatus::class,
    ];

    public function isCancelled(): bool
    {
        return $this->status === SessionStatus::CANCELLED;
    }

    public function cohort(): BelongsTo
    {
        return $this->belongsTo(Cohort::class);
    }

    public function lesson(): BelongsTo
    {
        return $this->belongsTo(Lesson::class);
    }

    // Attendance logs relationship
    public function participantIntervals(): HasMany
    {
        return $this->hasMany(CohortSessionParticipantInterval::class);
    }

    public function stats(): HasOne
    {
        return $this->hasOne(CohortSessionStat::class);
    }

    public function attendanceLogs(): HasMany
    {
        return $this->hasMany(CohortSessionAttendanceLog::class);
    }

    protected static function newFactory(): CohortSessionFactory
    {
        return CohortSessionFactory::new();
    }
}
