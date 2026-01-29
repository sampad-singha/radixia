<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('modules', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('program_id')->constrained('programs')->onDelete('cascade');

            $table->string('title'); // e.g., "Section 1: Basics"
            $table->text('description')->nullable();
            $table->integer('order_index')->default(0);

            $table->timestamps();
            $table->softDeletes();
        });

        // 2. LESSONS (The Content Templates)
        Schema::create('lessons', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('module_id')->constrained('modules')->onDelete('cascade');

            $table->string('title'); // e.g., "Routing & Controllers"
            $table->text('description')->nullable();
            $table->integer('duration_minutes')->default(40);
            $table->integer('order_index')->default(0);

            $table->timestamps();
            $table->softDeletes();
        });

        // 3. COHORT SESSIONS (The Actual Live Classes)
        Schema::create('cohort_sessions', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('cohort_id')->constrained('cohorts')->onDelete('cascade');

            // The Link: Which Lesson is being taught?
            $table->foreignUuid('lesson_id')->constrained('lessons')->onDelete('cascade');

            $table->dateTime('starts_at');
            $table->dateTime('ends_at');

            // Meeting Details
            $table->string('meeting_url')->nullable();
            $table->string('recording_url')->nullable();

            $table->enum('status', ['scheduled', 'live', 'completed', 'cancelled'])->default('scheduled');

            $table->timestamps();
            $table->softDeletes();

            $table->index(['cohort_id', 'starts_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('cohort_sessions');
        Schema::dropIfExists('lessons');
        Schema::dropIfExists('modules');
    }
};
