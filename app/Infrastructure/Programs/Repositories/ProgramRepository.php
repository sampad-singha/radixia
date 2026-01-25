<?php

namespace App\Infrastructure\Programs\Repositories;

use App\Domain\Programs\Entities\Program;
use App\Domain\Programs\Repositories\ProgramRepositoryInterface;
use Illuminate\Support\Collection;

class ProgramRepository implements ProgramRepositoryInterface
{
    public function create(array $data): Program
    {
        return Program::create($data);
    }

    public function update(Program $program, array $data): Program
    {
        $program->update($data);
        return $program->fresh();
    }

    public function findById(string $id): ?Program
    {
        return Program::query()->find($id);
    }

    public function findBySlug(string $slug): ?Program
    {
        return Program::query()
            ->where('slug', $slug)
            ->first();
    }

    public function allPublished(): Collection
    {
        return Program::query()
            ->where('is_published', true)
            ->orderBy('created_at', 'desc')
            ->get();
    }

    public function findWithCurriculum(string $idOrSlug): ?Program
    {
        return Program::query()
            ->where('id', $idOrSlug)
            ->orWhere('slug', $idOrSlug)
            ->with([
                'modules' => fn($q) => $q->orderBy('order_index'),
                'modules.lessons' => fn($q) => $q->orderBy('order_index')
            ])
            ->first();
    }
}