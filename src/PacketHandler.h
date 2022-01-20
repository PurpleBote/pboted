/**
 * Copyright (C) 2019-2022 polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
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

#include "Logging.h"
#include "Packet.h"

#define PBOTE_PROTOCOL_VERSION 4

namespace pbote
{
namespace packet
{

class IncomingRequest;

typedef bool (IncomingRequest::*incomingPacketHandler)(const std::shared_ptr<pbote::CommunicationPacket> &packet);
//typedef bool (OutgoingRequest::*outgoingPacketHandler)(const std::shared_ptr<pbote::CommunicationPacket> &packet);

class IncomingRequest {
 public:
  IncomingRequest();

  bool handleNewPacket(const std::shared_ptr<PacketForQueue>& packet);

 private:
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

  incomingPacketHandler i_handlers_[256];
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
