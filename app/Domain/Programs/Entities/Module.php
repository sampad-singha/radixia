<?php

namespace App\Domain\Programs\Entities;

use Database\Factories\ModuleFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * @property string $id
 * @property string $program_id
 * @property string $title
 * @property string|null $description
 * @property int $order_index
 * @property Program $program
 */
class Module extends Model
{
    use HasFactory, HasUuids, SoftDeletes;

    protected $fillable = ['program_id', 'title', 'description', 'order_index'];

    protected $casts = [
        'order_index' => 'integer',
        'deleted_at' => 'datetime',
    ];

    public function program(): BelongsTo
    {
        return $this->belongsTo(Program::class);
    }

    public function lessons(): HasMany
    {
        return $this->hasMany(Lesson::class)->orderBy('order_index');
    }

    protected static function newFactory(): ModuleFactory
    {
        return ModuleFactory::new();
    }
}
