<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class MfaMethod extends Model
{
    use HasUlids;
    protected $fillable = [
        'user_id', // Don't forget the Foreign Key if creating directly
        'type',
        'secret',
        'backup_codes',
        'is_default',
        'last_used_at',
    ];

    protected $hidden = [
        'secret',
        'backup_codes',
    ];

    protected $casts = [
        'data' => 'array',
        'is_default' => 'boolean',
        'last_used_at' => 'datetime',

        'secret' => 'encrypted:array',       // <--- CHANGE THIS
        'backup_codes' => 'encrypted:array', // <--- CHANGE THIS
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
