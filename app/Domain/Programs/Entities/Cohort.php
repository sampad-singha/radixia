<?php

namespace App\Domain\Programs\Entities;

use App\Domain\Programs\Enums\CohortStatus;
use App\Models\User;
use Database\Factories\CohortFactory;
use DateTimeInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
* @property string $program_id
* @property string $assigned_instructor_id
* @property string $name
* @property DateTimeInterface $start_date
* @property DateTimeInterface $end_date
* @property int $capacity
* @property float $price
* @property CohortStatus $status
**/

class Cohort extends Model
{
    /** @use HasFactory<CohortFactory> */
    use HasFactory, HasUuids, SoftDeletes;

    protected $fillable = [
        'program_id',
        'assigned_instructor_id',
        'name',
        'start_date',
        'end_date',
        'capacity',
        'price',
        'status', // 'scheduled', 'active', 'completed', 'cancelled'
    ];

    protected $casts = [
        'start_date' => 'date',
        'end_date' => 'date',
        'capacity' => 'integer',
        'price' => 'decimal:2',
        'deleted_at' => 'datetime',
        'status'     => CohortStatus::class,
    ];

    public function enrollments(): HasMany
    {
        return $this->hasMany(CohortEnrollment::class);
    }

    public function program(): BelongsTo
    {
        return $this->belongsTo(Program::class);
    }

    public function instructor(): BelongsTo
    {
        return $this->belongsTo(User::class, 'assigned_instructor_id');
    }

    public function sessions(): HasMany
    {
        return $this->hasMany(CohortSession::class);
    }

//    public function getSoldSeats(): int
//    {
//        // If loaded via withCount('enrollments'), use that.
//        // Otherwise, run the query.
//        return $this->enrollments_count ?? $this->enrollments()->count();
//    }
}
