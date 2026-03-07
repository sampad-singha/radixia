<?php

namespace App\Domain\Users\Entities;

use App\Models\User;
use Database\Factories\UserProfileFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class UserProfile extends Model
{
    use HasUuids;

    protected $fillable = [
        'user_id',
        'avatar_url',
        'bio',
        'city',
        'country',
        'timezone',
        'locale',
        'gender',
        'date_of_birth',
        'marketing_opt_in',
    ];

    protected $casts = [
        'marketing_opt_in' => 'boolean',
        'date_of_birth' => 'date',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    protected static function newFactory(): UserProfileFactory
    {
        return UserProfileFactory::new();
    }

}
