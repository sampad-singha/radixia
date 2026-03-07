<?php

namespace App\Models;

use App\Domain\Auth\Entities\SocialAccount;
use App\Domain\Mfa\Entities\MfaMethod;
use App\Domain\Programs\Entities\CohortEnrollment;
use App\Domain\Users\Entities\UserProfile;
use App\Notifications\VerifyEmailQueued;
use Database\Factories\UserFactory;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Fortify\TwoFactorAuthenticatable;
use Laravel\Sanctum\HasApiTokens;
use Spatie\Permission\Traits\HasRoles;

class User extends Authenticatable implements MustVerifyEmail
{
    /** @use HasFactory<UserFactory> */
    use HasFactory, Notifiable, HasApiTokens, TwoFactorAuthenticatable, HasUuids, HasRoles;

    protected string $guard_name = 'web';

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
        'is_password_set',
        'type',
        'secret',
        'is_default',
        'confirmed_at',
        'last_used_at',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var list<string>
     */
    protected $hidden = [
        'password',
        'remember_token',
        'two_factor_recovery_codes',
        'two_factor_secret',
        'pending_email',
        'pending_email_token',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
            'two_factor_confirmed_at' => 'datetime',
            'pending_email_token' => 'hashed',
            'pending_email_expires_at' => 'datetime',
            'is_password_set' => 'boolean',
        ];
    }

    public function socialAccounts(): HasMany
    {
        return $this->hasMany(SocialAccount::class);
    }

    public function mfaMethods(): HasMany
    {
        return $this->hasMany(MfaMethod::class);
    }

    public function profile(): HasOne
    {
        return $this->hasOne(UserProfile::class);
    }

    /**
     * Override the default email verification notification
     */
    public function sendEmailVerificationNotification(): void
    {
        // Use your new queued notification
        $this->notify(new VerifyEmailQueued);
    }

    public function cohortEnrollments(): HasMany
    {
        return $this->hasMany(CohortEnrollment::class);
    }

    public function isAdmin(): bool
    {
        return $this->hasRole('admin');
    }

    public function isInstructor(): bool
    {
        return $this->hasRole('instructor');
    }

}
