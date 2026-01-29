<?php

namespace App\Http\Requests\Api\V1\Program;

use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class UpdateProgramRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, ValidationRule|array|string>
     */
    public function rules(): array
    {
        return [\
            'title' => 'required|string|max:255',
            'change_slug' => 'required|boolean',
            Rule::unique('programs', 'slug')->ignore($this->route('program')),
            'description' => 'nullable|string',
            'short_description' => 'nullable|string|max:500',
            'level' => 'required|string|in:beginner,intermediate,advanced',
            'thumbnail_url' => 'nullable|url',
            'intro_video_url' => 'nullable|url',
        ];
    }
}
