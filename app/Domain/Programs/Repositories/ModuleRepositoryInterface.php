<?php

namespace App\Domain\Programs\Repositories;

use App\Domain\Programs\Entities\Module;
use Illuminate\Support\Collection;

interface ModuleRepositoryInterface
{
    public function create(array $data): Module;


    public function update(Module $module, array $data): Module;


    public function delete(Module $module): void;


    public function findById(string $id): ?Module;


    public function findByProgram(string $programId): Collection;

    public function updateOrderIndex(string $moduleId, int $newOrder);

    public function getLessonMaxIndex(string $moduleId): int;
}