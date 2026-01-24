<?php

namespace App\Domain\Programs\Repositories;

use App\Domain\Programs\Entities\Lesson;
use Illuminate\Support\Collection;

interface LessonRepositoryInterface
{
    public function create(array $data): Lesson;


    public function update(Lesson $lesson, array $data): Lesson;


    public function delete(Lesson $lesson): void;


    public function findById(string $id): ?Lesson;


    public function findByModule(string $moduleId): Collection;
}