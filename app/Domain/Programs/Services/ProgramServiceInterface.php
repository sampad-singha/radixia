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
    public function getProgramById(string $id): ?Program;
    public function listPublishedPrograms(): Collection;

    public function getProgramDetails(string $slugOrId): Program;

    public function createProgram(array $data): Program;

    public function updateProgram(Program $program, array $data): Program;

    public function archiveProgram(Program $program): Program;

    /**
     * Module Operations
     */
    public function addModuleToProgram(Program $program, array $data): Module;

    public function updateModule(Module $module, array $data): Module;

    public function deleteModule(Module $module): void;

    public function restoreModule(Module $module): Module;

    public function reorderModules(Program $program, array $orderedIds): void;

    /**
     * Lesson Operations
     */
    public function addLessonToModule(Module $module, array $data): Lesson;

    public function updateLesson(Lesson $lesson, array $data): Lesson;

    public function deleteLesson(Lesson $lesson): void;

    public function reorderLessons(Module $module, array $orderedIds): void;

    public function restoreLesson(Lesson $lesson): Lesson;
}