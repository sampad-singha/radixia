<?php

namespace App\Domain\Taxonomy\Entities;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Subcategory extends Model
{
    use HasUlids;

    protected $fillable = [
        'category_id',
        'name',
        'slug',
        'order_index',
        'is_active',
    ];

    protected $casts = [
        'is_active' => 'boolean',
    ];

    public function category(): BelongsTo
    {
        return $this->belongsTo(Category::class);
    }

    public function topics(): HasMany
    {
        return $this->hasMany(Topic::class);
    }
}
