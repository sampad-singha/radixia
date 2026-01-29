<?php

namespace App\Domain\Programs\Entities;

use Database\Factories\LessonFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * @property string $module_id
 * @property string $title
 * @property string|null $description
 * @property int $duration_minutes
 * @property int $order_index
 * @property Module $module
 */
class Lesson extends Model
{
    use HasFactory, HasUuids, SoftDeletes;

    protected $fillable = ['module_id', 'title', 'description', 'duration_minutes', 'order_index'];

    protected $casts = [
        'duration_minutes' => 'integer',
        'order_index' => 'integer',
        'deleted_at' => 'datetime',
    ];

    public function module(): BelongsTo
    {
        return $this->belongsTo(Module::class);
    }

    // "Show me every time this lesson was taught across all cohorts"
    public function sessions(): HasMany
    {
        return $this->hasMany(CohortSession::class);
    }

    protected static function newFactory(): LessonFactory
    {
        return LessonFactory::new();
    }
}
