<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class ProgramCohortResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        $now = now();

        $status = match (true) {
            $now->lt($this->start_date) => 'open',
            $now->between($this->start_date, $this->end_date) => 'running',
            default => 'ended',
        };

        return [
            'id' => $this->id,
            'name' => $this->name,

            'startDate' => $this->start_date?->toDateString(),
            'endDate' => $this->end_date?->toDateString(),
            'enrollDeadline' => $this->start_date?->toDateString(),

            'schedule' => $this->schedule,

            'instructor' => $this->instructor?->name,

            'price' => (float) $this->price,
            'originalPrice' => null,

            'seats' => $this->capacity,
            'seatsLeft' => max($this->capacity - $this->enrolled_count, 0),

            'status' => $status,
        ];
    }
}
