/**
 * Copyright (c) 2019-2021 polistern
 */

#ifndef PACKET_HANDLER_H__
#define PACKET_HANDLER_H__

#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <queue>
#include <string>
#include <thread>
#include <tuple>

#include "Log.h"
#include "Packet.h"

#define PBOTE_PROTOCOL_VERSION 4

namespace pbote {
namespace packet {

extern uint8_t PacketType[];

extern uint8_t CommunicationPreffix[];

class RequestHandler;
class IncomingRequest;
class OutgoingRequest;

typedef bool (IncomingRequest::*incomingPacketHandler)(const std::shared_ptr<pbote::CommunicationPacket> &packet);
//typedef bool (OutgoingRequest::*outgoingPacketHandler)(const std::shared_ptr<pbote::CommunicationPacket> &packet);

class IncomingRequest {
 public:
  IncomingRequest(RequestHandler &parent);
  ~IncomingRequest();

  bool handleNewPacket(const std::shared_ptr<PacketForQueue>& packet);

  bool receiveRelayRequest(const std::shared_ptr<pbote::CommunicationPacket>& packet);
  bool receiveRelayReturnRequest(const std::shared_ptr<pbote::CommunicationPacket>& packet);
  bool receiveFetchRequest(const std::shared_ptr<pbote::CommunicationPacket>& packet);
  bool receiveResponsePkt(const std::shared_ptr<pbote::CommunicationPacket>& packet);
  bool receivePeerListRequest(const std::shared_ptr<pbote::CommunicationPacket>& packet);
  ///
  bool receiveRetrieveRequest(const std::shared_ptr<pbote::CommunicationPacket>& packet);
  bool receiveDeletionQueryRequest(const std::shared_ptr<pbote::CommunicationPacket>& packet);
  bool receiveStoreRequest(const std::shared_ptr<pbote::CommunicationPacket>& packet);
  bool receiveEmailPacketDeleteRequest(const std::shared_ptr<pbote::CommunicationPacket>& packet);
  bool receiveIndexPacketDeleteRequest(const std::shared_ptr<pbote::CommunicationPacket>& packet);
  bool receiveFindClosePeersRequest(const std::shared_ptr<pbote::CommunicationPacket>& packet);

 private:
  RequestHandler &m_Parent;
  std::map<uint8_t, incomingPacketHandler> incomingPacketHandlers_;
};

class RequestHandler {
 public:
  RequestHandler();
  ~RequestHandler();

  void start();
  void stop();

  bool isRunning() const { return started_; };

 private:
  void run();

  bool started_;
  std::thread *m_PHandlerThread;
  queue_type m_recvQueue;
  queue_type m_sendQueue;
};

extern RequestHandler packet_handler;

} // namespace packet
} // namespace pbote

#endif // PACKET_HANDLER_H__