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
        Schema::create('features', function (Blueprint $table) {
            $table->uuid('id')->primary();

            // Polymorphic owner (Program / Course / Bundle etc)
            $table->uuidMorphs('featureable');

            // Feature content
            $table->string('content');

            // Lucide icon name (e.g., Clock, Award, Users)
            $table->string('icon')->nullable();

            $table->integer('order_index')->default(0);

            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('features');
    }
};
