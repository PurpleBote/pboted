/**
 * Copyright (C) 2019-2022, polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <random>

#include "DHTworker.h"
#include "PacketHandler.h"
#include "RelayWorker.h"

namespace pbote
{
namespace packet
{

RequestHandler packet_handler;

IncomingRequest::IncomingRequest (RequestHandler &owner) : m_owner (owner)
{
  // ToDo: re-make with std::function?
  i_handlers_[type::CommR] = &IncomingRequest::receiveRelayRequest;
  i_handlers_[type::CommK] = &IncomingRequest::receiveRelayReturnRequest;
  // i_handlers_[type::CommF] = &IncomingRequest::receiveFetchRequest;
  i_handlers_[type::CommN] = &IncomingRequest::receiveResponsePkt;
  i_handlers_[type::CommA] = &IncomingRequest::receivePeerListRequest;
  ///
  i_handlers_[type::CommQ] = &IncomingRequest::receiveRetrieveRequest;
  i_handlers_[type::CommY] = &IncomingRequest::receiveDeletionQueryRequest;
  i_handlers_[type::CommS] = &IncomingRequest::receiveStoreRequest;
  i_handlers_[type::CommD] = &IncomingRequest::receiveEmailPacketDeleteRequest;
  i_handlers_[type::CommX] = &IncomingRequest::receiveIndexPacketDeleteRequest;
  i_handlers_[type::CommF] = &IncomingRequest::receiveFindClosePeersRequest;
}

bool
IncomingRequest::handleNewPacket (const sp_queue_pkt &queuePacket)
{
  sp_comm_pkt packet = pbote::parseCommPacket (queuePacket);
  if (!packet)
    {
      LogPrint (eLogWarning, "Packet: Can't parse packet");
      return false;
    }

  /// First we need to check if ResponsePacket and CID in batches
  if (packet->type == type::CommN)
    {
      if (context.receive (packet))
        {
          LogPrint (eLogDebug, "Packet: Pass packet ", packet->type,
                    " to batch");
          return true;
        }
    }

  LogPrint (eLogDebug, "Packet: Non-batch packet with type ", packet->type);

  if (i_handlers_[packet->type])
    return (this->*(i_handlers_[packet->type])) (packet);
  else
    {
      LogPrint (eLogWarning, "Packet: Got unknown packet type ", packet->type);
      return false;
    }
}

/// not implemented
bool
IncomingRequest::receiveRelayRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Packet: receiveRelayRequest");
  // ToDo
  return true;
}

/// not implemented
bool
IncomingRequest::receiveRelayReturnRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Packet: receiveRelayReturnRequest");
  // ToDo
  return true;
}

/// not implemented
bool
IncomingRequest::receiveFetchRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Packet: receiveFetchRequest");
  // ToDo
  return true;
}

bool
IncomingRequest::receiveResponsePkt (const sp_comm_pkt &packet)
{
  LogPrint (eLogWarning, "Packet: Response: Unexpected Response received");
  LogPrint (eLogWarning, "Packet: Response: Sender: ", packet->from);

  ResponsePacket response;
  bool parsed = response.from_comm_packet (*packet, true);
  if (!parsed)
    {
      LogPrint (eLogWarning, "Packet: Response: Can't parse packet");
      return false;
    }

  LogPrint (eLogWarning,
            "Packet: Response: Status: ", unsigned (response.status),
            ", message: ", pbote::statusToString (response.status));

  if (response.length == 0)
    {
      LogPrint (eLogWarning, "Packet: Response: Empty packet");
      return true;
    }

  /// Peer List
  /// L for mhatta, P for str4d
  if (response.data[0] == (uint8_t)'L' || response.data[0] == (uint8_t)'P')
    {
      if (response.ver == (uint8_t)4)
        {
          LogPrint (eLogWarning, "Packet: Response: Peer List V4");
          return true;
        }
      else if (response.ver == (uint8_t)5)
        {
          LogPrint (eLogWarning, "Packet: Response: Peer List V5");
          return true;
        }
    }

  /// Index Packet
  if (response.data[0] == DataI)
    {
      LogPrint (eLogWarning, "Packet: Response: Index Packet received");
      return true;
    }

  /// Email Packet
  if (response.data[0] == DataE)
    {
      LogPrint (eLogWarning, "Packet: Response: Email Packet received");
      return true;
    }

  /// Directory Entry Packet
  if (response.data[0] == DataC)
    {
      LogPrint (eLogWarning,
                "Packet: Response: Directory Entry Packet received");
      return true;
    }

  LogPrint (eLogWarning,
            "Packet: Response: Unsupported, type: ", response.data[0],
            ", ver: ", unsigned (response.data[1]));

  return false;
}

bool
IncomingRequest::receivePeerListRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Packet: receivePeerListRequest");
  if (packet->ver == 4)
    {
      m_owner.get_IO_service ().post (
          std::bind (&pbote::relay::RelayWorker::peerListRequestV4,
                     &pbote::relay::relay_worker, packet));
      return true;
    }
  else if (packet->ver == 5)
    {
      m_owner.get_IO_service ().post (
          std::bind (&pbote::relay::RelayWorker::peerListRequestV5,
                     &pbote::relay::relay_worker, packet));
      return true;
    }
  else
    {
      LogPrint (eLogWarning, "Packet: receivePeerListRequest: Unknown, ver: ",
                unsigned (packet->ver), ", type: ", packet->type);
      return false;
    }
}

///////////////////////////////////////////////////////////////////////////////

bool
IncomingRequest::receiveRetrieveRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Packet: receiveRetrieveRequest");
  if (packet->ver >= 4 && packet->type == type::CommQ)
    {
      m_owner.get_IO_service ().post (
          std::bind (&pbote::kademlia::DHTworker::receiveRetrieveRequest,
                     &pbote::kademlia::DHT_worker, packet));
      return true;
    }

  LogPrint (eLogWarning, "Packet: receiveRetrieveRequest: Unknown, ver: ",
            unsigned (packet->ver), ", type: ", packet->type);
  return false;
}

bool
IncomingRequest::receiveDeletionQueryRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Packet: receiveDeletionQueryRequest");
  /// Y for mhatta
  if (packet->ver >= 4 && packet->type == type::CommY)
    {
      m_owner.get_IO_service ().post (
          std::bind (&pbote::kademlia::DHTworker::receiveDeletionQuery,
                     &pbote::kademlia::DHT_worker, packet));
      return true;
    }

  /// L for str4d
  if (packet->ver >= 4 && packet->type == (uint8_t)'L')
    {
      m_owner.get_IO_service ().post (
          std::bind (&pbote::kademlia::DHTworker::receiveDeletionQuery,
                     &pbote::kademlia::DHT_worker, packet));
      return true;
    }

  LogPrint (eLogWarning, "Packet: receiveDeletionQueryRequest: Unknown, ver: ",
            unsigned (packet->ver), ", type: ", packet->type);
  return false;
}

bool
IncomingRequest::receiveStoreRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Packet: receiveStoreRequest");
  if (packet->ver >= 4 && packet->type == type::CommS)
    {
      m_owner.get_IO_service ().post (
          std::bind (&pbote::kademlia::DHTworker::receiveStoreRequest,
                     &pbote::kademlia::DHT_worker, packet));
      return true;
    }

  LogPrint (eLogWarning, "Packet: receiveStoreRequest: Unknown, ver: ",
            unsigned (packet->ver), ", type: ", packet->type);
  return false;
}

bool
IncomingRequest::receiveEmailPacketDeleteRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Packet: receiveEmailPacketDeleteRequest");
  if (packet->ver >= 4 && packet->type == type::CommD)
    {
      m_owner.get_IO_service ().post (std::bind (
          &pbote::kademlia::DHTworker::receiveEmailPacketDeleteRequest,
          &pbote::kademlia::DHT_worker, packet));
      return true;
    }

  LogPrint (eLogWarning,
            "Packet: receiveEmailPacketDeleteRequest: Unknown, ver: ",
            unsigned (packet->ver), ", type: ", packet->type);
  return false;
}

bool
IncomingRequest::receiveIndexPacketDeleteRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Packet: receiveIndexPacketDeleteRequest");
  if (packet->ver >= 4 && packet->type == type::CommX)
    {
      m_owner.get_IO_service ().post (std::bind (
          &pbote::kademlia::DHTworker::receiveIndexPacketDeleteRequest,
          &pbote::kademlia::DHT_worker, packet));
      return true;
    }

  LogPrint (eLogWarning,
            "Packet: receiveIndexPacketDeleteRequest: Unknown, ver: ",
            unsigned (packet->ver), ", type: ", packet->type);
  return false;
}

bool
IncomingRequest::receiveFindClosePeersRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Packet: receiveFindClosePeersRequest");
  if (packet->ver >= 4 && packet->type == type::CommF)
    {
      m_owner.get_IO_service ().post (
          std::bind (&pbote::kademlia::DHTworker::receiveFindClosePeers,
                     &pbote::kademlia::DHT_worker, packet));
      return true;
    }

  LogPrint (eLogWarning,
            "Packet: receiveFindClosePeersRequest: Unknown, ver: ",
            unsigned (packet->ver), ", type: ", packet->type);
  return false;
}

RequestHandler::RequestHandler ()
    : running (false), m_PHandlerThread (nullptr),
      m_IO_service_thread (nullptr), m_recvQueue (nullptr),
      m_sendQueue (nullptr), m_IO_work (get_IO_service ())
{
}

RequestHandler::~RequestHandler ()
{
  stop ();

  if (m_PHandlerThread)
    {
      m_PHandlerThread->join ();
      m_PHandlerThread = nullptr;
    }
}

void
RequestHandler::start ()
{
  m_recvQueue = context.getRecvQueue ();
  m_sendQueue = context.getSendQueue ();
  running = true;

  if (m_PHandlerThread)
    m_PHandlerThread = nullptr;

  if (m_IO_service_thread)
    m_IO_service_thread = nullptr;

  m_PHandlerThread.reset (
      new std::thread (std::bind (&RequestHandler::run, this)));
  m_IO_service_thread.reset (
      new std::thread (std::bind (&RequestHandler::run_IO_service, this)));
}

void
RequestHandler::stop ()
{
  running = false;

  m_IO_service.stop ();

  if (m_IO_service_thread)
    {
      m_IO_service_thread->join ();
      m_IO_service_thread = nullptr;
    }

  m_recvQueue = nullptr;
  m_sendQueue = nullptr;

  LogPrint (eLogInfo, "PacketHandler: Stopped");
}

void
RequestHandler::run ()
{
  LogPrint (eLogInfo, "PacketHandler: Started");

  while (running)
    {
      auto packet = m_recvQueue->GetNextWithTimeout (PACKET_RECEIVE_TIMEOUT);

      if (!packet)
        continue;

      LogPrint (eLogDebug, "PacketHandler: Got new packet");

      IncomingRequest handler (*this);
      /// If successful, we move on to processing the next packet
      if (handler.handleNewPacket (packet))
        continue;

      LogPrint (eLogWarning, "PacketHandler: Parsing failed, skipped");

      pbote::ResponsePacket response;
      response.status = pbote::StatusCode::INVALID_PACKET;
      response.length = 0;
      auto data = response.toByte ();

      m_sendQueue->Put (std::make_shared<PacketForQueue> (
          packet->destination, data.data (), data.size ()));
    }
}

void
RequestHandler::run_IO_service ()
{
  while (running)
    {
      std::this_thread::sleep_for (std::chrono::seconds (2));

      try
        {
          size_t executed = m_IO_service.run ();
          if (executed > 0)
            LogPrint (eLogDebug,
                      "PacketHandler: IO service round results: ", executed);
        }
      catch (std::exception &ex)
        {
          LogPrint (eLogError, "PacketHandler: IO service runtime exception: ",
                    ex.what ());
        }
    }
}

} // namespace packet
} // namespace pbote
