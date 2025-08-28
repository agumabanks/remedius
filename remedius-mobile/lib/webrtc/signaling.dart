import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';

class Signaling {
  final FirebaseFirestore db = FirebaseFirestore.instance;
  final String callId;
  RTCPeerConnection? pc;

  Signaling(this.callId);

  Future<void> start(bool isCaller, List<Map<String,dynamic>> iceServers) async {
    final config = {'iceServers': iceServers};
    pc = await createPeerConnection(config);

    pc!.onIceCandidate = (c) {
      if (c.candidate != null) {
        db.collection('signals').doc(callId).collection('candidates').add({
          'candidate': c.toMap(),
          'ts': FieldValue.serverTimestamp()
        });
      }
    };

    final callRef = db.collection('signals').doc(callId);
    if (isCaller) {
      final offer = await pc!.createOffer();
      await pc!.setLocalDescription(offer);
      await callRef.set({'offer': offer.sdp, 'type': offer.type, 'participants': []});
      callRef.snapshots().listen((snap) async {
        final data = snap.data();
        if (data?['answer'] != null && pc!.remoteDescription == null) {
          await pc!.setRemoteDescription(
            RTCSessionDescription(data!['answer'], 'answer'));
        }
      });
    } else {
      final snap = await callRef.get();
      final offer = snap.data()?['offer'];
      await pc!.setRemoteDescription(RTCSessionDescription(offer, 'offer'));
      final answer = await pc!.createAnswer();
      await pc!.setLocalDescription(answer);
      await callRef.update({'answer': answer.sdp});
    }

    callRef.collection('candidates').snapshots().listen((query) {
      for (final doc in query.docChanges) {
        final c = doc.doc.data()?['candidate'];
        if (c != null) pc!.addCandidate(RTCIceCandidate(c['candidate'], c['sdpMid'], c['sdpMLineIndex']));
      }
    });
  }
}
