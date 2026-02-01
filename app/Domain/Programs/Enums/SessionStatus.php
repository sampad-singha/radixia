<?php

namespace App\Domain\Programs\Enums;

enum SessionStatus: string
{
    case SCHEDULED = 'scheduled';
    case LIVE = 'live';
    case COMPLETED = 'completed';
    case CANCELLED = 'cancelled';
}
