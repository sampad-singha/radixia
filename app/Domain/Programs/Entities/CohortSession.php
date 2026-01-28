<?php

namespace App\Domain\Programs\Entities;

use Database\Factories\LessonFactory;
use DateTimeInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * @property string cohort_id
 * @property string lesson_id
 * @property DateTimeInterface starts_at
 * @property DateTimeInterface ends_at
 * @property string meeting_url
 * @property string recording_url
 * @property string status
 */
class CohortSession extends Model
{
    use HasFactory, HasUuids, SoftDeletes;

    protected $fillable = [
        'cohort_id',
        'lesson_id',
        'starts_at',
        'ends_at',
        'meeting_url',
        'recording_url',
        'status'
    ];

    protected $casts = [
        'starts_at' => 'datetime',
        'ends_at' => 'datetime',
    ];

    public function cohort(): BelongsTo
    {
        return $this->belongsTo(Cohort::class);
    }

    public function lesson(): BelongsTo
    {
        return $this->belongsTo(Lesson::class);
    }

    protected static function newFactory(): LessonFactory
    {
        return LessonFactory::new();
    }
}
