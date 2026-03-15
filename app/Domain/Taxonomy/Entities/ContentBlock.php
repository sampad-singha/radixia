<?php

namespace App\Domain\Taxonomy\Entities;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;

class ContentBlock extends Model
{
    use HasUlids;

    protected $fillable = [
        'blockable_id',
        'blockable_type',
        'type',
        'content',
        'order_index',
    ];

    protected $casts = [
        'id' => 'string',
        'blockable_id' => 'string',
    ];

    public function blockable(): MorphTo
    {
        return $this->morphTo();
    }
}
