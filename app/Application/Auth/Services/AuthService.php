<?php

namespace App\Application\Auth\Services;

use App\Domain\Auth\Services\AuthServiceInterface;
use App\Domain\Users\Repositories\UserRepositoryInterface;
use App\Exceptions\Domain\Auth\Exceptions\InvalidCredentialsException;
use App\Models\User;
use Exception;
use Illuminate\Support\Facades\Hash;
use Laravel\Fortify\Contracts\CreatesNewUsers;

class AuthService implements AuthServiceInterface
{
    public function __construct(
        private readonly UserRepositoryInterface $users,
        private readonly CreatesNewUsers $createsNewUsers, // Fortify action
    ) {}

    public function register(array $data): array
    {
        $user = $this->createsNewUsers->create($data); // uses App\Actions\Fortify\CreateNewUser [page:5]

        $token = $user->createToken($data['device_name'])->plainTextToken; // Sanctum token issuance [page:4]

        return ['user' => $user, 'token' => $token];
    }

    /**
     * @throws Exception
     */
    public function login(array $data): array
    {
        $user = $this->users->findByEmail($data['email']);

        if (! $user || ! Hash::check($data['password'], $user->password)) {
            throw new InvalidCredentialsException();
        }

        $token = $user->createToken($data['device_name'])->plainTextToken; // Sanctum token issuance [page:4]

        return ['user' => $user, 'token' => $token];
    }

    public function logout(User $user): void
    {
        $user->currentAccessToken()?->delete(); // revoke current token [page:4]
    }
}