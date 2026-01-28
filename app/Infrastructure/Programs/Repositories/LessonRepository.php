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

    public function getTrashedByModuleId(string $moduleId): Collection
    {
        return Lesson::onlyTrashed()->where('module_id', $moduleId)->get();
    }

    public function updateOrderIndex(string $lessonId, int $newOrder): void
    {
        Lesson::where('id', $lessonId)->update(['order_index' => $newOrder]);
    }

    public function findWithTrashed(string $id): ?Lesson
    {
        /** @var Lesson|null $lesson */
        $lesson = Lesson::withTrashed()->find($id);

        return $lesson;
    }

    public function restore(Lesson $lesson): bool
    {
        return $lesson->restore();
    }

    public function isIndexOccupied(string $moduleId, int $index): bool
    {
        // We only care about LIVE lessons (not trashed ones)
        return Lesson::where('module_id', $moduleId)
            ->where('order_index', $index)
            ->exists();
    }
}