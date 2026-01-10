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
        Schema::create('social_accounts', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('provider_name'); // 'google', 'facebook'
            $table->string('provider_id');
            $table->text('token');           // Store Access Token
            $table->text('refresh_token')->nullable(); // For offline access
            $table->integer('expires_in')->nullable(); // Token lifespan in seconds
            $table->string('avatar')->nullable();
            $table->timestamps();

            $table->unique(['provider_name', 'provider_id']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('social_accounts');
    }
};
