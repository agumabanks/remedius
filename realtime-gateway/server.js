import 'dotenv/config';
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import Redis from 'ioredis';
import axios from 'axios';

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: (process.env.CORS_ORIGIN || '*').split(',') }
});

const redis = new Redis({
  host: process.env.REDIS_HOST || '127.0.0.1',
  port: Number(process.env.REDIS_PORT || 6379),
  password: process.env.REDIS_PASSWORD || undefined
});

await redis.psubscribe('*');
redis.on('pmessage', (pattern, channel, message) => {
  try {
    const payload = JSON.parse(message);
    if (payload?.event && payload?.channel) {
      io.to(payload.channel).emit(payload.event, payload.data);
    }
  } catch {}
});

io.on('connection', (socket) => {
  socket.on('thread:join', ({ threadId }) => {
    socket.join(`thread.${threadId}`);
  });

  socket.on('message:send', async ({ threadId, body, attachmentUrl, token }) => {
    try {
      await axios.post(`${process.env.LARAVEL_URL}/api/threads/${threadId}/messages`,
        { body, attachment_url: attachmentUrl },
        { headers: { Authorization: `Bearer ${token}` } }
      );
    } catch (err) {
      socket.emit('error', { message: 'Failed to send message' });
    }
  });
});

app.get('/health', (_, res)=>res.json({ok:true}));
server.listen(process.env.PORT || 8081, ()=> {
  console.log('Realtime gateway running on', process.env.PORT || 8081);
});
