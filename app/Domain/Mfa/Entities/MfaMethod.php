<?php

namespace App\Domain\Mfa\Entities;

use App\Models\User;
use Database\Factories\MfaMethodFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class MfaMethod extends Model
{
    use HasUuids, HasFactory;
    protected $fillable = [
        'user_id',
        'type',
        'secret',
        'backup_codes',
        'is_default',
        'confirmed_at',
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
        'confirmed_at' => 'datetime',

        'secret' => 'encrypted:array',
        'backup_codes' => 'encrypted:array',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    protected static function newFactory(): MfaMethodFactory
    {
        return MfaMethodFactory::new();
    }
}
