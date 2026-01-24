<?php

namespace App\Domain\Programs\Entities;

use Database\Factories\LessonFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class CohortSession extends Model
{
    use HasFactory, HasUuids;

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
