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
        Schema::create('cohort_session_stats', function (Blueprint $table) {
            $table->uuid('id')->primary();

            $table->foreignUuid('cohort_session_id')
                ->unique()
                ->constrained('cohort_sessions')
                ->cascadeOnDelete();

            // Aggregates
            $table->bigInteger('total_meeting_ms')->default(0);
            $table->bigInteger('instructor_active_ms')->default(0);

            // Control flags
            $table->boolean('finalized')->default(false);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('cohort_session_stats');
    }
};
