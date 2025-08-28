<?php

use Illuminate\Support\Facades\Broadcast;

Broadcast::channel('thread.{threadId}', function ($user, $threadId) {
    // TODO: verify membership via participants array on MessageThread
    return true;
});
