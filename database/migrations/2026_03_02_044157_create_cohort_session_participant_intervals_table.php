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
        Schema::create('cohort_session_participant_intervals', function (Blueprint $table) {
            $table->uuid('id')->primary();

            $table->foreignUuid('cohort_session_id')
                ->constrained('cohort_sessions')
                ->cascadeOnDelete();

            $table->string('participant_id')->index(); // external ID

            $table->foreignUuid('user_id')
                ->nullable()
                ->constrained('users')
                ->nullOnDelete();

            $table->boolean('is_moderator')->default(false);

            $table->bigInteger('joined_at');  // ms
            $table->bigInteger('left_at')->nullable();
            $table->bigInteger('duration_ms')->nullable();

            $table->timestamps();

            $table->index(['cohort_session_id', 'user_id']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('cohort_session_participant_intervals');
    }
};
