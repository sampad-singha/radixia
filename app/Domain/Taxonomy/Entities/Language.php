<?php

namespace App\Domain\Taxonomy\Entities;

use App\Domain\Programs\Entities\Program;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Language extends Model
{
    use HasUlids;

    protected $fillable = [
        'name',
        'code',
        'native_name',
        'flag_url',
        'is_rtl',
        'is_active',
    ];

    protected $casts = [
        'is_rtl' => 'boolean',
        'is_active' => 'boolean',
    ];

    public function programs(): HasMany
    {
        return $this->hasMany(Program::class);
    }
}
