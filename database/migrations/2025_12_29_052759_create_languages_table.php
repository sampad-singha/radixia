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
        Schema::create('languages', function (Blueprint $table) {
            $table->uuid('id')->primary();

            $table->string('name');          // English
            $table->string('code', 10)->unique(); // en, bn, hi
            $table->string('native_name')->nullable(); // ইংরেজি
            $table->string('flag_url')->nullable(); // URL to flag image
            $table->boolean('is_rtl')->default(false); // Right-to-left language
            $table->boolean('is_active')->default(true);

            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('languages');
    }
};
