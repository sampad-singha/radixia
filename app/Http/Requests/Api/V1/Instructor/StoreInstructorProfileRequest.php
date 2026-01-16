<?php

namespace App\Http\Requests\Api\V1\Instructor;

use Illuminate\Foundation\Http\FormRequest;

class StoreInstructorProfileRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'headline' => ['nullable', 'string', 'max:255'],
            'bio' => ['nullable', 'string', 'max:5000'],
            'intro_video_url' => ['nullable', 'url', 'max:255'],
        ];
    }
}
