<?php

namespace App\Http\Resources\Api\V1\Instructor;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class InstructorProfileResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'headline' => $this->headline,
            'bio' => $this->bio,
            'intro_video_url' => $this->intro_video_url,
            'is_verified' => $this->is_verified,
            'verification_status' => $this->verification_status,
            'verification_notes' => $this->verification_notes,
            'created_at' => $this->created_at,
            'updated_at' => $this->updated_at,
        ];
    }
}
