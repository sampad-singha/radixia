<?php

namespace App\Http\Controllers\Api\V1\Auth;

use App\Domain\Auth\Services\AuthServiceInterface;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\Auth\LoginRequest;
use App\Http\Requests\Api\V1\Auth\RegisterRequest;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function __construct(private readonly AuthServiceInterface $auth) {}

    public function register(RegisterRequest $request)
    {
        $result = $this->auth->register($request->validated());

        return response()->json([
            'data' => [
                'token' => $result['token'],
                'user' => $result['user'],
            ],
        ], 201);
    }

    public function login(LoginRequest $request)
    {
        $result = $this->auth->login($request->validated());

        return response()->json([
            'data' => [
                'token' => $result['token'],
                'user' => $result['user'],
            ],
        ]);
    }

    public function logout(Request $request)
    {
        $this->auth->logout($request->user());

        return response()->json(['data' => ['message' => 'Logged out']]);
    }

    public function me(Request $request)
    {
        return response()->json(['data' => ['user' => $request->user()]]);
    }
}
