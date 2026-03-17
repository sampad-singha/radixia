<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Str;

class ProgramDetailsResource extends JsonResource
{
    public function __construct($resource, private array $stats = [])
    {
        parent::__construct($resource);
    }

    public function toArray(Request $request): array
    {
        $program = $this;

        $topic = $program->topics->first();
        $subcategory = $topic?->subcategory;
        $category = $subcategory?->category;

        $instructor = $program->instructor;
        $profile = $instructor?->instructorProfile;

        return [
            'id' => $program->id,
            'slug' => $program->slug,
            'title' => $program->title,
            'subtitle' => $program->short_description,

            'category' => $category ? [
                'id' => $category->id,
                'name' => $category->name,
            ] : null,

            'subcategory' => $subcategory ? [
                'id' => $subcategory->id,
                'name' => $subcategory->name,
            ] : null,

            'topic' => $topic ? [
                'id' => $topic->id,
                'name' => $topic->name,
                'slug' => $topic->slug,
            ] : null,

            'level' => Str::ucfirst($program->level),

            'badges' => [],

            'rating' => [
                'average' => round($program->rating_avg ?? 0, 1),
                'count' => $program->rating_count ?? 0,
            ],

            'studentsCount' => $program->students_count ?? 0,

            'language' => $program->language?->name,

            'updatedAt' => optional($program->latest_cohort_created_at)?->toDateString(),

            'stats' => [
                'durationHours' => round(($program->duration_minutes ?? 0) / 60, 1),
                'lessons' => $program->lessons_count ?? 0,
                'modules' => $program->modules_count ?? 0,
                'level'   => Str::ucfirst($program->level), // first letter uppercase
            ],

            'instructor' => [
                'id' => $instructor?->id,
                'name' => $instructor?->name,
                'title' => $profile?->headline,
                'avatar' => $instructor?->avatar_url,
                'bio' => $profile?->bio,

                'rating' => round($this->stats['rating_avg'] ?? 0, 1),
                'students' => $this->stats['students'] ?? 0,
                'courses' => $this->stats['courses'] ?? 0,
            ],

            'previewVideo' => [
                'path' => $program->intro_video_url,
                'thumbnail' => $program->thumbnail_url,
            ],

            'features' => $program->features
                ->map(function ($feature) {
                    return [
                        'content' => $feature->content,
                        'icon' => $feature->icon,
                    ];
                })
                ->values(),

            'pricing' => [
                'price' => $program->price ?? null,
                'originalPrice' => null,
                'currency' => 'BDT',
                'discountPercent' => null,
                'offerEnds' => null,
            ],
        ];
    }
}
