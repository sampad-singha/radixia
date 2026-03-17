<?php

namespace App\Http\Resources;

use Illuminate\Http\Resources\Json\JsonResource;

class ProgramOverviewResource extends JsonResource
{
    public function toArray($request): array
    {
        return [
            'learningOutcomes' => $this->contentBlocks
                ->where('type', 'learning_outcome')
                ->pluck('content')
                ->values(),

            'prerequisites' => $this->contentBlocks
                ->where('type', 'prerequisite')
                ->pluck('content')
                ->values(),

            'targetAudience' => $this->contentBlocks
                ->where('type', 'target_audience')
                ->pluck('content')
                ->values(),

            'description' => $this->description,
        ];
    }
}
