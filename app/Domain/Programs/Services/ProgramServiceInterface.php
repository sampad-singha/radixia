<?php

namespace App\Domain\Programs\Services;

use App\Domain\Programs\Entities\Lesson;
use App\Domain\Programs\Entities\Module;
use App\Domain\Programs\Entities\Program;
use Illuminate\Support\Collection;

interface ProgramServiceInterface
{
    /**
     * Program Operations
     */
    public function listPublishedPrograms(): Collection;

    public function getProgramDetails(string $slugOrId): Program;

    public function createProgram(array $data): Program;

    public function updateProgram(string $id, array $data): Program;

    public function archiveProgram(string $id): Program;

    /**
     * Module Operations
     */
    public function addModuleToProgram(string $programId, array $data): Module;

    public function updateModule(string $moduleId, array $data): Module;

    public function reorderModules(string $programId, array $orderedIds): void;

    /**
     * Lesson Operations
     */
    public function addLessonToModule(string $moduleId, array $data): Lesson;

    public function updateLesson(string $lessonId, array $data): Lesson;

    public function deleteLesson(string $lessonId): void;

    public function reorderLessons(string $moduleId, array $orderedIds): void;
}