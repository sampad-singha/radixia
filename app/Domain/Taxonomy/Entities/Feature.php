<?php

namespace App\Domain\Taxonomy\Entities;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;

class Feature extends Model
{
    protected $fillable = [
        'featureable_id',
        'featureable_type',
        'content',
        'icon',
        'order_index',
    ];

    protected $casts = [
        'id' => 'string',
        'featureable_id' => 'string',
    ];

    public function featureable(): MorphTo
    {
        return $this->morphTo();
    }
}
