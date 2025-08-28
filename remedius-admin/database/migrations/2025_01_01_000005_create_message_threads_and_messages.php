<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
  public function up(): void {
    Schema::create('message_threads', function (Blueprint $t) {
      $t->id();
      $t->string('subject')->nullable();
      $t->json('participants');
      $t->timestamps();
    });

    Schema::create('messages', function (Blueprint $t) {
      $t->id();
      $t->foreignId('thread_id')->constrained('message_threads')->cascadeOnDelete();
      $t->foreignId('sender_id')->constrained('users')->cascadeOnDelete();
      $t->text('body')->nullable();
      $t->string('attachment_url')->nullable();
      $t->timestamp('read_at')->nullable();
      $t->timestamps();
      $t->index(['thread_id','created_at']);
    });
  }
  public function down(): void {
    Schema::dropIfExists('messages');
    Schema::dropIfExists('message_threads');
  }
};
