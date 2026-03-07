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
        Schema::create('cohort_session_attendance_logs', function (Blueprint $table) {
            $table->uuid('id')->primary();

            $table->foreignUuid('cohort_session_id')
                ->constrained('cohort_sessions')
                ->cascadeOnDelete();

            $table->foreignUuid('user_id')
                ->constrained('users')
                ->cascadeOnDelete();

            // Raw computed durations
            $table->bigInteger('student_active_ms')->default(0);
            $table->bigInteger('student_instructor_overlap_ms')->default(0);

            // Ratios
            $table->decimal('ratio_total', 5, 4)->default(0);
            $table->decimal('ratio_instructor', 5, 4)->default(0);

            // Final decision
            $table->boolean('attended')->default(false);

            $table->timestamps();

            $table->unique(['cohort_session_id', 'user_id']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('cohort_session_attendance_logs');
    }
};
