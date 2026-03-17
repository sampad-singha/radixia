<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class ProgramCurriculumResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'modules' => $this->modules->map(function ($module) {

                return [
                    'title' => $module->title,
                    'description' => $module->description,

                    'lessons' => $module->lessons->map(function ($lesson) {

                        return [
                            'title' => $lesson->title,
                            'type' => $lesson->type ?? 'video',

                            'duration' => $this->formatDuration($lesson->duration_minutes),

                            // TODO: replace with real logic later
                            'locked' => true,
                            'preview' => false,
                        ];
                    })->values(),
                ];

            })->values(),
        ];
    }

    private function formatDuration(?int $minutes): ?string
    {
        if (!$minutes) {
            return null;
        }

        $hours = floor($minutes / 60);
        $mins = $minutes % 60;

        if ($hours > 0) {
            return sprintf('%d:%02d', $hours, $mins);
        }

        return sprintf('%d:%02d', $mins, 0);
    }
}
