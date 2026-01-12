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
        Schema::create('user_profiles', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('user_id')
                ->unique()
                ->constrained('users')
                ->cascadeOnDelete();

            // General Info
            $table->string('avatar_url')->nullable();
            $table->text('bio')->nullable()->comment('General "About Me" for the user');

            // Location & Localization
            $table->string('city')->nullable();
            $table->string('country')->nullable();
            $table->string('timezone')->default('Asia/Dhaka')->nullable();
            $table->string('locale', 10)->default('en')->comment('Preferred UI language');

            // Demographics (Useful for student analytics)
            $table->enum('gender', ['male', 'female', 'other'])->nullable();
            $table->date('date_of_birth')->nullable();

            // Preferences
            $table->boolean('marketing_opt_in')->default(false);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('user_profiles');
    }
};
