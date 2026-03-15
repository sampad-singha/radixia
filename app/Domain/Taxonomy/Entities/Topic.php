<?php

namespace App\Domain\Taxonomy\Entities;

use App\Domain\Programs\Entities\Program;
use Database\Factories\TopicFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

class Topic extends Model
{
    /** @use HasFactory<TopicFactory> */
    use HasFactory, HasUuids;

    protected $fillable = [
        'subcategory_id',
        'name',
        'slug',
        'description',
        'order_index',
        'is_active',
    ];

    protected $casts = [
        'is_active' => 'boolean',
    ];

    public function subcategory(): BelongsTo
    {
        return $this->belongsTo(Subcategory::class);
    }

    public function programs(): BelongsToMany
    {
        return $this->belongsToMany(Program::class, 'program_topic');
    }

    protected static function newFactory(): TopicFactory
    {
        return TopicFactory::new();
    }
}
