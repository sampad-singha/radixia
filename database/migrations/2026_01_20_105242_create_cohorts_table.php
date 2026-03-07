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

            // Relationships
            $table->foreignUuid('program_id')->constrained('programs')->onDelete('cascade');

            $table->foreignUuid('assigned_instructor_id')->constrained('users')->onDelete('cascade');

            // Core Info
            $table->string('name');
            $table->date('start_date');
            $table->date('end_date')->nullable();

            // Inventory
            $table->integer('capacity')->unsigned();

            // Pricing (Base Price Only)
            $table->decimal('price', 10, 2);

            // Lifecycle
            $table->enum('status', ['scheduled', 'active', 'completed', 'cancelled'])
                ->default('scheduled')
                ->comment('scheduled(D), active, completed, cancelled');

            $table->timestamps();
            $table->softDeletes();

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
