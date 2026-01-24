<?php

namespace App\Infrastructure\Programs\Repositories;

use App\Domain\Programs\Entities\Lesson;
use App\Domain\Programs\Repositories\LessonRepositoryInterface;
use Illuminate\Support\Collection;

class LessonRepository implements LessonRepositoryInterface
{
    public function create(array $data): Lesson
    {
        return Lesson::create($data);
    }


    public function update(Lesson $lesson, array $data): Lesson
    {
        $lesson->update($data);
        return $lesson->fresh();
    }


    public function delete(Lesson $lesson): void
    {
        $lesson->delete();
    }


    public function findById(string $id): ?Lesson
    {
        return Lesson::query()->find($id);
    }


    public function findByModule(string $moduleId): Collection
    {
        return Lesson::query()
            ->where('module_id', $moduleId)
            ->orderBy('order_index')
            ->get();
    }
}