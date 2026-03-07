<?php

namespace App\Http\Requests\Api\V1\Program;

use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;

class UpdateSessionRequest extends FormRequest
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
        return [
            // Allowed updates
            'starts_at' => ['sometimes', 'date'],
            'ends_at'   => ['sometimes', 'date', 'after:starts_at'],

            // Explicitly forbidden (defense-in-depth)
            'cohort_id'      => ['prohibited'],
            'lesson_id'      => ['prohibited'],
            'room_id'        => ['prohibited'],
            'recording_url'  => ['prohibited'],
            'status'         => ['prohibited'],
        ];
    }
}
