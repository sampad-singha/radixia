<?php

namespace App\Http\Requests\Api\V1\Auth;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class SocialLoginRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    protected function prepareForValidation(): void
    {
        // Merge the route parameter 'provider' into the request data for validation
        $this->merge([
            'provider' => $this->route('provider'),
        ]);
    }

    public function rules(): array
    {
        return [
            // Validate the provider against the config list
            'provider' => ['required', 'string', Rule::in(config('services.social_providers', []))],
            'code'    => ['required', 'string'],
        ];
    }
}