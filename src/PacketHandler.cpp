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
  i_handlers[type::CommR] = &IncomingRequest::receiveRelayRequest;
  i_handlers[type::CommK] = &IncomingRequest::receiveRelayReturnRequest;
  // i_handlers[type::CommF] = &IncomingRequest::receiveFetchRequest;
  i_handlers[type::CommN] = &IncomingRequest::receiveResponsePkt;
  i_handlers[type::CommA] = &IncomingRequest::receivePeerListRequest;
  ///
  i_handlers[type::CommQ] = &IncomingRequest::receiveRetrieveRequest;
  i_handlers[type::CommY] = &IncomingRequest::receiveDeletionQueryRequest;
  i_handlers[type::CommS] = &IncomingRequest::receiveStoreRequest;
  i_handlers[type::CommD] = &IncomingRequest::receiveEmailPacketDeleteRequest;
  i_handlers[type::CommX] = &IncomingRequest::receiveIndexPacketDeleteRequest;
  i_handlers[type::CommF] = &IncomingRequest::receiveFindClosePeersRequest;
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

  if (i_handlers[packet->type])
    return (this->*(i_handlers[packet->type])) (packet);
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
  LogPrint (eLogDebug, "Packet: RelayRequest");
  // ToDo
  return true;
}

/// not implemented
bool
IncomingRequest::receiveRelayReturnRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Packet: RelayReturnRequest");
  // ToDo
  return true;
}

/// not implemented
bool
IncomingRequest::receiveFetchRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Packet: FetchRequest");
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
  if (response.data[0] == (uint8_t)'L')
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
  LogPrint (eLogDebug, "Packet: PeerListRequest");
  if (packet->ver == 4)
    {
      auto req_thread = m_owner.get_request_thread ();
      //req_thread = new std::thread ([pbote::relay::relay_worker](sp_comm_pkt packet) { peerListRequestV4 (packet); });
      req_thread = std::make_shared<std::thread> (std::bind (
          &pbote::relay::RelayWorker::peerListRequestV4,
          &pbote::relay::relay_worker, packet));
      req_thread->join ();

      return true;
    }
  else if (packet->ver == 5)
    {
      auto req_thread = m_owner.get_request_thread ();
      req_thread = std::make_shared<std::thread> (std::bind (
          &pbote::relay::RelayWorker::peerListRequestV5,
          &pbote::relay::relay_worker, packet));
      req_thread->join ();

      return true;
    }
  else
    {
      LogPrint (eLogWarning, "Packet: PeerListRequest: Unknown, ver: ",
                unsigned (packet->ver), ", type: ", packet->type);
      return false;
    }
}

///////////////////////////////////////////////////////////////////////////////

bool
IncomingRequest::receiveRetrieveRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Packet: RetrieveRequest");
  if (packet->ver >= 4 && packet->type == type::CommQ)
    {
      auto req_thread = m_owner.get_request_thread ();
      req_thread = std::make_shared<std::thread> (std::bind (
          &pbote::kademlia::DHTworker::receiveRetrieveRequest,
          &pbote::kademlia::DHT_worker, packet));
      req_thread->join ();

      return true;
    }

  LogPrint (eLogWarning, "Packet: RetrieveRequest: Unknown, ver: ",
            unsigned (packet->ver), ", type: ", packet->type);
  return false;
}

bool
IncomingRequest::receiveDeletionQueryRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Packet: DeletionQueryRequest");

  if (packet->ver >= 4 && packet->type == type::CommY)
    {
      auto req_thread = m_owner.get_request_thread ();
      req_thread = std::make_shared<std::thread> (std::bind (
          &pbote::kademlia::DHTworker::receiveDeletionQuery,
          &pbote::kademlia::DHT_worker, packet));
      req_thread->join ();

      return true;
    }

  LogPrint (eLogWarning, "Packet: DeletionQueryRequest: Unknown, ver: ",
            unsigned (packet->ver), ", type: ", packet->type);
  return false;
}

bool
IncomingRequest::receiveStoreRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Packet: StoreRequest");
  if (packet->ver >= 4 && packet->type == type::CommS)
    {
      auto req_thread = m_owner.get_request_thread ();
      req_thread = std::make_shared<std::thread> (std::bind (
          &pbote::kademlia::DHTworker::receiveStoreRequest,
          &pbote::kademlia::DHT_worker, packet));
      req_thread->join ();

      return true;
    }

  LogPrint (eLogWarning, "Packet: StoreRequest: Unknown, ver: ",
            unsigned (packet->ver), ", type: ", packet->type);
  return false;
}

bool
IncomingRequest::receiveEmailPacketDeleteRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Packet: EmailPacketDeleteRequest");
  if (packet->ver >= 4 && packet->type == type::CommD)
    {
      auto req_thread = m_owner.get_request_thread ();
      req_thread = std::make_shared<std::thread> (std::bind (
          &pbote::kademlia::DHTworker::receiveEmailPacketDeleteRequest,
          &pbote::kademlia::DHT_worker, packet));
      req_thread->join ();

      return true;
    }

  LogPrint (eLogWarning,
            "Packet: EmailPacketDeleteRequest: Unknown, ver: ",
            unsigned (packet->ver), ", type: ", packet->type);
  return false;
}

bool
IncomingRequest::receiveIndexPacketDeleteRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Packet: IndexPacketDeleteRequest");
  if (packet->ver >= 4 && packet->type == type::CommX)
    {
      auto req_thread = m_owner.get_request_thread ();
      req_thread = std::make_shared<std::thread> (std::bind (
          &pbote::kademlia::DHTworker::receiveIndexPacketDeleteRequest,
          &pbote::kademlia::DHT_worker, packet));
      req_thread->join ();

      return true;
    }

  LogPrint (eLogWarning,
            "Packet: IndexPacketDeleteRequest: Unknown, ver: ",
            unsigned (packet->ver), ", type: ", packet->type);
  return false;
}

bool
IncomingRequest::receiveFindClosePeersRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Packet: FindClosePeersRequest");
  if (packet->ver >= 4 && packet->type == type::CommF)
    {
      auto req_thread = m_owner.get_request_thread ();
      req_thread = std::make_shared<std::thread> (std::bind (
          &pbote::kademlia::DHTworker::receiveFindClosePeers,
          &pbote::kademlia::DHT_worker, packet));
      req_thread->join ();

      return true;
    }

  LogPrint (eLogWarning,
            "Packet: FindClosePeersRequest: Unknown, ver: ",
            unsigned (packet->ver), ", type: ", packet->type);
  return false;
}

RequestHandler::RequestHandler ()
    : m_running (false),
      m_main_thread (nullptr),
      m_request_thread (nullptr),
      m_recv_queue (nullptr),
      m_send_queue (nullptr)
{
}

RequestHandler::~RequestHandler ()
{
  stop ();

  if (m_main_thread)
    {
      m_main_thread->join ();
      m_main_thread = nullptr;
    }

  if (m_request_thread)
    {
      m_request_thread->join ();
      m_request_thread = nullptr;
    }
}

void
RequestHandler::start ()
{
  m_recv_queue = context.getRecvQueue ();
  m_send_queue = context.getSendQueue ();
  m_running = true;

  if (m_main_thread)
    m_main_thread = nullptr;

  if (m_request_thread)
    m_request_thread = nullptr;

  m_main_thread.reset (
      new std::thread (std::bind (&RequestHandler::run, this)));
}

void
RequestHandler::stop ()
{
  m_running = false;

  if (m_main_thread)
    {
      m_main_thread->join ();
      m_main_thread = nullptr;
    }

  if (m_request_thread)
    {
      m_request_thread->join ();
      m_request_thread = nullptr;
    }

  m_recv_queue = nullptr;
  m_send_queue = nullptr;

  LogPrint (eLogInfo, "PacketHandler: Stopped");
}

std::shared_ptr<std::thread>
RequestHandler::get_request_thread ()
{
  if (m_request_thread)
    {
      if (m_request_thread->joinable ())
        m_request_thread->join ();
    }

  return m_request_thread;
}

void
RequestHandler::run ()
{
  LogPrint (eLogInfo, "PacketHandler: Started");

  while (m_running)
    {
      auto packet = m_recv_queue->GetNextWithTimeout (PACKET_RECEIVE_TIMEOUT);

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

      m_send_queue->Put (std::make_shared<PacketForQueue> (
          packet->destination, data.data (), data.size ()));
    }
}

} // namespace packet
} // namespace pbote
