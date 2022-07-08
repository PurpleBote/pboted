/**
 * Copyright (C) 2019-2022, polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef PACKET_HANDLER_H__
#define PACKET_HANDLER_H__

#include <boost/asio.hpp>
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

  incomingPacketHandler i_handlers_[256];
  RequestHandler& m_owner;
};

class RequestHandler
{
public:
  RequestHandler ();
  ~RequestHandler ();

  void start ();
  void stop ();

  boost::asio::io_service&
  get_IO_service ()
  {
    return m_IO_service;
  }

  bool
  isRunning () const
  {
    return running;
  };

private:
  void run ();
  void run_IO_service ();

  bool running;
  std::unique_ptr<std::thread> m_PHandlerThread, m_IO_service_thread;
  queue_type m_recvQueue, m_sendQueue;

  boost::asio::io_service m_IO_service;
  boost::asio::io_service::work m_IO_work;
};

extern RequestHandler packet_handler;

} // namespace packet
} // namespace pbote

#endif // PACKET_HANDLER_H__
