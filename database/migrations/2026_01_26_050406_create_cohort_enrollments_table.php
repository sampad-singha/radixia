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
        Schema::create('cohort_enrollments', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('user_id')->constrained('users')->cascadeOnDelete();
            $table->foreignUuid('cohort_id')->constrained('cohorts')->cascadeOnDelete();

            // Lifecycle & Seat Management
            $table->enum('status', ['pending', 'active', 'expired', 'cancelled']);
            $table->timestamp('expires_at')->nullable();  // Crucial for the 30-min reservation
            $table->timestamp('activated_at')->nullable(); // When payment was confirmed

            // Payment Info (Specific to this enrollment instance)
            $table->string('transaction_id')->nullable();
            $table->decimal('amount_paid', 10, 2)->nullable();

            $table->timestamps();
            $table->softDeletes();

            // Prevent double enrollment in the same cohort
            $table->unique(['user_id', 'cohort_id']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('cohort_enrollments');
    }
};
