<?php

namespace App\Domain\Instructors\Entities;

use App\Models\User;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

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

    protected static function newFactory()
    {
        //return InstructorProfileFactory::new();
    }
}
