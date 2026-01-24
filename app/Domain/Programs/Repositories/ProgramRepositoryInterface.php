<?php

namespace App\Domain\Programs\Repositories;

use App\Domain\Programs\Entities\Program;
use Illuminate\Support\Collection;

interface ProgramRepositoryInterface
{
    public function create(array $data): Program;


    public function update(Program $program, array $data): Program;


    public function findById(string $id): ?Program;


    public function findBySlug(string $slug): ?Program;


    public function allPublished(): Collection;
}