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

namespace pbote
{
namespace packet
{

using sp_comm_pac = std::shared_ptr<pbote::CommunicationPacket>;

class IncomingRequest;

typedef bool (IncomingRequest::*incomingPacketHandler) (
    const sp_comm_pac &packet);
// typedef bool (OutgoingRequest::*outgoingPacketHandler)(const sp_comm_pac
// &packet);

class IncomingRequest
{
public:
  IncomingRequest ();

  bool handleNewPacket (const std::shared_ptr<PacketForQueue> &packet);

private:
  bool receiveRelayRequest (const sp_comm_pac &packet);
  bool receiveRelayReturnRequest (const sp_comm_pac &packet);
  bool receiveFetchRequest (const sp_comm_pac &packet);
  bool receiveResponsePkt (const sp_comm_pac &packet);
  bool receivePeerListRequest (const sp_comm_pac &packet);
  ///
  bool receiveRetrieveRequest (const sp_comm_pac &packet);
  bool receiveDeletionQueryRequest (const sp_comm_pac &packet);
  bool receiveStoreRequest (const sp_comm_pac &packet);
  bool receiveEmailPacketDeleteRequest (const sp_comm_pac &packet);
  bool receiveIndexPacketDeleteRequest (const sp_comm_pac &packet);
  bool receiveFindClosePeersRequest (const sp_comm_pac &packet);

  incomingPacketHandler i_handlers_[256];
};

class RequestHandler
{
public:
  RequestHandler ();
  ~RequestHandler ();

  void start ();
  void stop ();

  bool
  isRunning () const
  {
    return started_;
  };

private:
  void run ();

  bool started_;
  std::thread *m_PHandlerThread;
  queue_type m_recvQueue;
  queue_type m_sendQueue;
};

extern RequestHandler packet_handler;

} // namespace packet
} // namespace pbote

#endif // PACKET_HANDLER_H__
