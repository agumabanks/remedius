import 'package:socket_io_client/socket_io_client.dart' as IO;

class ChatSocket {
  late IO.Socket _socket;

  ChatSocket(String url, {required String token}) {
    _socket = IO.io(url, IO.OptionBuilder()
        .setTransports(['websocket'])
        .setExtraHeaders({'Authorization': 'Bearer $token'})
        .build());
  }

  void connectThread(int threadId, void Function(dynamic) onMessage) {
    _socket.onConnect((_) {
      _socket.emit('thread:join', {'threadId': threadId});
    });
    _socket.on('message.sent', onMessage);
  }

  void sendMessage(int threadId, String body, String token, {String? attachmentUrl}) {
    _socket.emit('message:send', {
      'threadId': threadId,
      'body': body,
      'attachmentUrl': attachmentUrl,
      'token': token
    });
  }

  void disconnect(){ _socket.dispose(); }
}
