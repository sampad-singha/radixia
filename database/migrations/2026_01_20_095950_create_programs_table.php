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
        Schema::create('programs', function (Blueprint $table) {
            $table->uuid('id')->primary();
            // Core Info
            $table->string('title');
            $table->string('slug')->unique();
            $table->text('description')->nullable();
            $table->text('short_description')->nullable();

            // Categorization
            $table->enum('level', ['beginner', 'intermediate', 'advanced'])->default('beginner');

            // Media
            $table->string('thumbnail_url')->nullable();
            $table->string('intro_video_url')->nullable();

            // Visibility
            $table->enum('status', ['draft', 'published', 'archived'])->default('draft');

            // Instructor (owner)
            $table->foreignUuid('instructor_id')->constrained('users')->onDelete('cascade');

            $table->foreignUuid('language_id')->nullable()->constrained('languages')->nullOnDelete();

            $table->timestamps();
            $table->softDeletes();

            // Indexes
            $table->index('status');
            $table->index('instructor_id');
            $table->index('slug');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('programs');
    }
};
