<?php

namespace App\Domain\Instructors\Entities;

use App\Domain\Taxonomy\Entities\Review;
use App\Models\User;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\MorphMany;

class InstructorProfile extends Model
{
    use HasUuids;

    protected $fillable = [
        'user_id',
        'headline',
        'bio',
        'intro_video_url',
        'is_verified',
        'verification_status',
        'verification_notes',
    ];

    protected $casts = [
        'is_verified' => 'boolean',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function reviews(): MorphMany
    {
        return $this->morphMany(Review::class, 'reviewable');
    }

    protected static function newFactory()
    {
        //return InstructorProfileFactory::new();
    }
}
