<?php

namespace App\Domain\Programs\Entities;

use App\Models\User;
use Database\Factories\CohortEnrollmentFactory;
use DateTime;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * @property string $id
 * @property string $user_id
 * @property string $cohort_id
 * @property string $status
 * @property string|null $transaction_id
 * @property float|null $amount_paid
 * @property DateTime|null $expires_at
 * @property DateTime|null $activated_at
 * @property DateTime|null $created_at
 * @property DateTime|null $updated_at
 * @property DateTime|null $deleted_at
 * */
class CohortEnrollment extends Model
{
    /** @use HasFactory<CohortEnrollmentFactory> */
    use HasFactory, HasUuids, SoftDeletes;

    protected $fillable = [
        'user_id',
        'cohort_id',
        'status',
        'transaction_id',
        'amount_paid',
        'expires_at',
        'activated_at',
    ];

    protected $casts = [
        'expires_at' => 'datetime',
        'activated_at' => 'datetime',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function cohort(): BelongsTo
    {
        return $this->belongsTo(Cohort::class);
    }
}
