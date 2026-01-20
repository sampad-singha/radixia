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
        Schema::create('cohorts', function (Blueprint $table) {
            $table->uuid('id')->primary();

            // Parent Program
            $table->foreignUuid('program_id')->constrained('programs')->onDelete('cascade');

            // Specific Instructor (Optional override)
            // If null, falls back to program->instructor_id
            $table->foreignUuid('instructor_id')->nullable()->constrained('users')->onDelete('set null');

            // Core Info
            $table->string('name'); // e.g., "Batch 01", "January 2026"
            $table->date('start_date');
            $table->date('end_date')->nullable();

            // Capacity & Sales
            $table->integer('capacity')->unsigned();
            $table->integer('sold_seats')->default(0);

            // Pricing (Snapshot, can differ from Program default)
            $table->decimal('price', 10, 2);
            $table->decimal('discount_price', 10, 2)->nullable();

            // State
            $table->enum('status', ['open', 'full', 'closed', 'completed', 'cancelled'])->default('open');

            $table->timestamps();
            $table->softDeletes();

            // Indexes
            $table->index(['program_id', 'status']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('cohorts');
    }
};
