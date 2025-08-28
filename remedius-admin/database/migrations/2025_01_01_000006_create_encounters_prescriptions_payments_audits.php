<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
  public function up(): void {
    Schema::create('encounters', function (Blueprint $t) {
      $t->id();
      $t->foreignId('appointment_id')->constrained()->cascadeOnDelete();
      $t->foreignId('doctor_id')->constrained('users')->cascadeOnDelete();
      $t->foreignId('patient_id')->constrained('users')->cascadeOnDelete();
      $t->text('notes')->nullable();
      $t->json('diagnoses')->nullable();
      $t->json('attachments')->nullable();
      $t->timestamps();
    });

    Schema::create('prescriptions', function (Blueprint $t) {
      $t->id();
      $t->foreignId('encounter_id')->constrained()->cascadeOnDelete();
      $t->string('pdf_url')->nullable();
      $t->enum('status', ['draft','issued','paid','cancelled'])->default('draft');
      $t->timestamps();
    });

    Schema::create('payments', function (Blueprint $t) {
      $t->id();
      $t->morphs('payable');
      $t->string('provider');
      $t->string('provider_ref')->nullable();
      $t->integer('amount_cents');
      $t->string('currency', 8)->default('UGX');
      $t->enum('status', ['pending','succeeded','failed'])->default('pending');
      $t->json('meta')->nullable();
      $t->timestamps();
    });

    Schema::create('audit_logs', function (Blueprint $t) {
      $t->id();
      $t->foreignId('user_id')->nullable()->constrained()->nullOnDelete();
      $t->string('action');
      $t->string('entity_type')->nullable();
      $t->unsignedBigInteger('entity_id')->nullable();
      $t->json('payload')->nullable();
      $t->ipAddress('ip')->nullable();
      $t->timestamps();
    });
  }
  public function down(): void {
    Schema::dropIfExists('audit_logs');
    Schema::dropIfExists('payments');
    Schema::dropIfExists('prescriptions');
    Schema::dropIfExists('encounters');
  }
};
