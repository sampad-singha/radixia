<?php

namespace App\Domain\Users\Repositories;

use App\Models\User;

interface UserRepositoryInterface
{
    public function findByEmail(string $email): ?User;
    public function create(array $data): User;
    public function findById(int $id): ?User;
}
