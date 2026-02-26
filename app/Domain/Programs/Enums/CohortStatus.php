<?php

namespace App\Domain\Programs\Enums;

enum CohortStatus: string
{
    case SCHEDULED = 'scheduled';
    case ACTIVE    = 'active';
    case COMPLETED = 'completed';
    case CANCELLED = 'cancelled';
}
