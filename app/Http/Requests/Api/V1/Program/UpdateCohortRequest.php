<?php

namespace App\Http\Requests\Api\V1\Program;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class UpdateCohortRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'name' => ['sometimes', 'string', 'max:255'],
            'start_date' => ['sometimes', 'date'],
            'end_date' => ['sometimes', 'date', 'after_or_equal:start_date'],
            'status' => ['sometimes', 'string', Rule::in(['scheduled', 'active', 'completed', 'cancelled'])],
            'capacity' => ['sometimes', 'integer', 'min:1'],
            'price' => ['sometimes', 'numeric', 'min:0'],
            'assigned_instructor_id' => ['sometimes', Rule::exists('users', 'id')],
        ];
    }

    /**
     * Custom messages for better instructor UX
     */
    public function messages(): array
    {
        return [
            'capacity.min' => 'Capacity cannot be less than the number of students already enrolled.',
            'end_date.after_or_equal' => 'The cohort must end on or after the start date.',
        ];
    }
}
