<?php

namespace App\Infrastructure\Programs\Repositories;

use App\Domain\Programs\Entities\Module;
use App\Domain\Programs\Repositories\ModuleRepositoryInterface;
use Illuminate\Support\Collection;

class ModuleRepository implements ModuleRepositoryInterface
{
    public function create(array $data): Module
    {
        return Module::create($data);
    }


    public function update(Module $module, array $data): Module
    {
        $module->update($data);
        return $module->fresh();
    }


    public function delete(Module $module): void
    {
        $module->delete();
    }


    public function findById(string $id): ?Module
    {
        return Module::query()->find($id);
    }


    public function findByProgram(string $programId): Collection
    {
        return Module::query()
            ->where('program_id', $programId)
            ->orderBy('order_index')
            ->get();
    }
}