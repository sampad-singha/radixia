<?php

namespace App\Domain\Programs\Entities;

use App\Domain\Taxonomy\Entities\Topic;
use App\Models\User;
use Database\Factories\ProgramFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * @property string $title
 * @property string $slug
 * @property string|null $description
 * @property string|null $short_description
 * @property string $level
 * @property string|null $thumbnail_url
 * @property string|null $intro_video_url
 * @property string $status
 * @property string $instructor_id
 */
class Program extends Model
{
    /** @use HasFactory<ProgramFactory> */
    use HasFactory, HasUuids, SoftDeletes;

    protected $fillable = [
        'title',
        'slug',
        'description',
        'short_description',
        'level',
        'thumbnail_url',
        'intro_video_url',
        'status',
        'instructor_id',
    ];

    protected $casts = [
        'id' => 'string',
        'instructor_id' => 'string',
        'deleted_at' => 'datetime',
    ];

    public function instructor(): BelongsTo
    {
        return $this->belongsTo(User::class, 'instructor_id');
    }

    public function topics(): BelongsToMany
    {
        return $this->belongsToMany(Topic::class, 'program_topic');
    }

    public function cohorts(): HasMany
    {
        return $this->hasMany(Cohort::class);
    }

    public function modules(): HasMany
    {
        return $this->hasMany(Module::class);
    }

    protected static function newFactory(): ProgramFactory
    {
        return ProgramFactory::new();
    }
}
