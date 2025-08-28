<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\MessageThread;
use App\Models\Message;
use App\Events\MessageSent;

class ChatController extends Controller
{
    public function send(Request $request, MessageThread $thread)
    {
        // TODO: policy: ensure $request->user() is a participant
        $msg = $thread->messages()->create([
            'sender_id' => $request->user()->id,
            'body' => $request->string('body'),
            'attachment_url' => $request->string('attachment_url', null),
        ]);

        broadcast(new MessageSent($msg))->toOthers();
        return response()->json($msg, 201);
    }
}
