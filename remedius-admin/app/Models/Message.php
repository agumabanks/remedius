<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Message extends Model
{
    protected $fillable = ['thread_id','sender_id','body','attachment_url','read_at'];
    protected $casts = ['read_at' => 'datetime'];

    public function thread(){ return $this->belongsTo(MessageThread::class); }
    public function sender(){ return $this->belongsTo(User::class, 'sender_id'); }
}
