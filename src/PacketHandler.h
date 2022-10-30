/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#pragma once
#ifndef PBOTED_SRC_PACKET_HANDLER_H
#define PBOTED_SRC_PACKET_HANDLER_H

#include <thread>

#include "NetworkWorker.h"
#include "Packet.h"

namespace bote
{

/// Timeout in msec
#define PACKET_RECEIVE_TIMEOUT 500

class IncomingRequest;
class RequestHandler;

typedef bool (IncomingRequest::*incomingPacketHandler) (
    const sp_comm_pkt &packet);
// typedef bool (OutgoingRequest::*outgoingPacketHandler)(const sp_comm_pkt
// &packet);

class IncomingRequest
{
public:
  IncomingRequest (RequestHandler& owner);

  bool handleNewPacket (const sp_queue_pkt &packet);

private:
  bool receiveRelayRequest (const sp_comm_pkt &packet);
  bool receiveRelayReturnRequest (const sp_comm_pkt &packet);
  bool receiveFetchRequest (const sp_comm_pkt &packet);
  bool receiveResponsePkt (const sp_comm_pkt &packet);
  bool receivePeerListRequest (const sp_comm_pkt &packet);
  ///
  bool receiveRetrieveRequest (const sp_comm_pkt &packet);
  bool receiveDeletionQueryRequest (const sp_comm_pkt &packet);
  bool receiveStoreRequest (const sp_comm_pkt &packet);
  bool receiveEmailPacketDeleteRequest (const sp_comm_pkt &packet);
  bool receiveIndexPacketDeleteRequest (const sp_comm_pkt &packet);
  bool receiveFindClosePeersRequest (const sp_comm_pkt &packet);

  incomingPacketHandler i_handlers[256];
  RequestHandler& m_owner;
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
    return m_running;
  };

  std::shared_ptr<std::thread> get_request_thread ();

private:
  void run ();

  bool m_running;
  std::unique_ptr<std::thread> m_main_thread;
  std::shared_ptr<std::thread> m_request_thread;
};

extern RequestHandler packet_handler;

} // namespace bote

#endif // PBOTED_SRC_PACKET_HANDLER_H
