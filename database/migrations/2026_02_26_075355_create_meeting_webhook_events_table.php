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
        Schema::create('meeting_webhook_events', function (Blueprint $table) {
            $table->uuid('id')->primary();

            $table->string('source')->index(); // jaas / jitsi
            $table->string('event_type')->index();
            $table->string('room_id')->index(); // JaaS → fqn/ Prosody → room / conference
            $table->string('session_id')->nullable()->index();// JaaS → sessionId/ Prosody → often null
            $table->string('participant_id')->nullable()->index();// JaaS → participantId/ Prosody → occupant_id / jid node
            $table->string('participant_name')->nullable();
            $table->boolean('is_moderator')->nullable();
            $table->bigInteger('event_timestamp')->index();
            $table->string('idempotency_key')->nullable();
            $table->json('raw_payload');
            $table->boolean('processed')->default(false);
            $table->timestamps();

            $table->unique(['source', 'idempotency_key']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('meeting_webhook_events');
    }
};
