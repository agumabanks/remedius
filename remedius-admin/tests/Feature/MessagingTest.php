<?php

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use App\Events\MessageSent;
use App\Models\MessageThread;
use App\Models\User;
use Laravel\Sanctum\Sanctum;

uses(RefreshDatabase::class);

it('stores and broadcasts a message', function () {
    Event::fake([MessageSent::class]);
    $alice = User::factory()->create();
    $bob = User::factory()->create();
    $thread = MessageThread::create(['participants'=>[$alice->id,$bob->id],'subject'=>'Consult']);
    Sanctum::actingAs($alice);

    $resp = $this->postJson("/api/threads/{$thread->id}/messages", ['body'=>'Hello']);
    $resp->assertCreated()->assertJson(['body'=>'Hello']);

    Event::assertDispatched(MessageSent::class);
});
