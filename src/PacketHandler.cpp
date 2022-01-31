/**
 * Copyright (C) 2019-2022 polistern
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

IncomingRequest::IncomingRequest ()
{
  // ToDo: re-make with std::function?
  i_handlers_[type::CommR] = &IncomingRequest::receiveRelayRequest;
  i_handlers_[type::CommK] = &IncomingRequest::receiveRelayReturnRequest;
  // i_handlers_[type::CommF] = &IncomingRequest::receiveFetchRequest;
  i_handlers_[type::CommN] = &IncomingRequest::receiveResponsePkt;
  i_handlers_[type::CommA] = &IncomingRequest::receivePeerListRequest;

  i_handlers_[type::CommQ] = &IncomingRequest::receiveRetrieveRequest;
  i_handlers_[type::CommY] = &IncomingRequest::receiveDeletionQueryRequest;
  i_handlers_[type::CommS] = &IncomingRequest::receiveStoreRequest;
  i_handlers_[type::CommD] = &IncomingRequest::receiveEmailPacketDeleteRequest;
  i_handlers_[type::CommX] = &IncomingRequest::receiveIndexPacketDeleteRequest;
  i_handlers_[type::CommF] = &IncomingRequest::receiveFindClosePeersRequest;
}

bool
IncomingRequest::handleNewPacket (
    const std::shared_ptr<PacketForQueue> &queuePacket)
{
  sp_comm_pac packet = pbote::parseCommPacket (queuePacket);
  if (!packet)
    {
      LogPrint (eLogWarning, "Packet: can't parse packet");
      return false;
    }

  /// First we need to check CID in batches
  // ToDo: check if we got Response Packet?
  if (context.receive (packet))
    {
      LogPrint (eLogDebug, "Packet: Pass packet ", packet->type, " to batch");
      return true;
    }

  LogPrint (eLogDebug, "Packet: Non-batch packet with type ",
            packet->type);

  if (i_handlers_[packet->type])
    return (this->*(i_handlers_[packet->type])) (packet);
  else
    {
      LogPrint (eLogWarning, "Packet: Got unknown packet type");
      return false;
    }
}

/// not implemented
bool
IncomingRequest::receiveRelayRequest (const sp_comm_pac &packet)
{
  LogPrint (eLogDebug, "Packet: receiveRelayRequest");
  // ToDo
  return true;
}

/// not implemented
bool
IncomingRequest::receiveRelayReturnRequest (const sp_comm_pac &packet)
{
  LogPrint (eLogDebug, "Packet: receiveRelayReturnRequest");
  // ToDo
  return true;
}

/// not implemented
bool
IncomingRequest::receiveFetchRequest (const sp_comm_pac &packet)
{
  LogPrint (eLogDebug, "Packet: receiveFetchRequest");
  // ToDo
  return true;
}

bool
IncomingRequest::receiveResponsePkt (const sp_comm_pac &packet)
{
  LogPrint (eLogWarning,
            "Packet: receiveResponsePkt: Unexpected Response received");
  LogPrint (eLogWarning, "Packet: receiveResponsePkt: Sender: ", packet->from);

  size_t offset = 0;
  uint8_t status;
  uint16_t dataLen;

  std::memcpy (&status, packet->payload.data (), 1);
  offset += 1;

  LogPrint (eLogWarning,
            "Packet: receiveResponsePkt: Status: ", unsigned (status),
            ", message: ", pbote::statusToString (status));

  std::memcpy (&dataLen, packet->payload.data () + offset, sizeof dataLen);
  dataLen = ntohs (dataLen);
  offset += 2;

  LogPrint (eLogWarning, "Packet: receiveResponsePkt: size: ",
            (packet->payload.size () - offset), ", dataLen: ", dataLen);

  if ((packet->payload.size () - offset) != dataLen)
    LogPrint (eLogWarning, "Packet: receiveResponsePkt: Size mismatch: size: ",
              (packet->payload.size () - offset), ", dataLen: ", dataLen);

  if (dataLen == 0)
    {
      LogPrint (eLogWarning, "Packet: receiveResponsePkt: Empty packet");
      return true;
    }

  std::vector<byte> data = { packet->payload.data () + offset,
                             packet->payload.data () + offset + dataLen };

  /// Peer List
  /// L for mhatta, P for str4d
  if (data[0] == (uint8_t)'L' || data[0] == (uint8_t)'P')
    {
      if (packet->ver == (uint8_t)4)
        {
          LogPrint (eLogWarning,
                    "Packet: receiveResponsePkt: Peer List, type: ", data[0],
                    ", ver: ", unsigned (data[1]));
          return pbote::relay::relay_worker.receivePeerListV4 (
              data.data (), dataLen);
        }
      else if (packet->ver == (uint8_t)5)
        {
          LogPrint (eLogWarning,
                    "Packet: receiveResponsePkt: Peer List, type: ", data[0],
                    ", ver: ", unsigned (data[1]));
          return pbote::relay::relay_worker.receivePeerListV5 (
              data.data (), dataLen);
        }
      else
        {
          LogPrint (eLogWarning,
                    "Packet: receiveResponsePkt: Unsupported type: ", data[0],
                    ", ver: ", unsigned (data[1]));
        }
    }

  /// Index Packet
  if (data[0] == (uint8_t)'I')
    {
      LogPrint (eLogWarning,
                "Packet: receiveResponsePkt: Index Packet received");
      return true;
    }

  /// Email Packet
  if (data[0] == (uint8_t)'E')
    {
      LogPrint (eLogWarning,
                "Packet: receiveResponsePkt: Email Packet received");
      return true;
    }

  /// Directory Entry Packet
  if (data[0] == (uint8_t)'C')
    {
      LogPrint (eLogWarning,
                "Packet: receiveResponsePkt: Directory Entry Packet received");
      return true;
    }

  LogPrint (eLogWarning, "Packet: receiveResponsePkt: type: ", data[0],
            ", ver: ", unsigned (data[1]));
  LogPrint (eLogWarning,
            "Packet: receiveResponsePkt: Unsupported data packet type");
  return false;
}

bool
IncomingRequest::receivePeerListRequest (const sp_comm_pac &packet)
{
  LogPrint (eLogDebug, "Packet: receivePeerListRequest");
  if (packet->ver == 4)
    {
      pbote::relay::relay_worker.peerListRequestV4 (packet->from,
                                                          packet->cid);
      return true;
    }
  else if (packet->ver == 5)
    {
      pbote::relay::relay_worker.peerListRequestV5 (packet->from,
                                                          packet->cid);
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
IncomingRequest::receiveRetrieveRequest (const sp_comm_pac &packet)
{
  LogPrint (eLogDebug, "Packet: receiveRetrieveRequest");
  if (packet->ver == 4 && packet->type == type::CommQ)
    {
      pbote::kademlia::DHT_worker.receiveRetrieveRequest (packet);
      return true;
    }
  LogPrint (eLogWarning, "Packet: receiveRetrieveRequest: Unknown, ver: ",
            unsigned (packet->ver), ", type: ", packet->type);
  return false;
}

bool
IncomingRequest::receiveDeletionQueryRequest (const sp_comm_pac &packet)
{
  LogPrint (eLogDebug, "Packet: receiveDeletionQueryRequest");
  /// Y for mhatta
  if (packet->ver == 4 && packet->type == type::CommY)
    {
      pbote::kademlia::DHT_worker.receiveDeletionQuery (packet);
      return true;
    }
  /// L for str4d
  if (packet->ver == 4 && packet->type == (uint8_t)'L')
    {
      pbote::kademlia::DHT_worker.receiveDeletionQuery (packet);
      return true;
    }

  LogPrint (eLogWarning, "Packet: receiveDeletionQueryRequest: Unknown, ver: ",
            unsigned (packet->ver), ", type: ", packet->type);
  return false;
}

bool
IncomingRequest::receiveStoreRequest (const sp_comm_pac &packet)
{
  LogPrint (eLogDebug, "Packet: receiveStoreRequest");
  if (packet->ver == 4 && packet->type == type::CommS)
    {
      pbote::kademlia::DHT_worker.receiveStoreRequest (packet);
      return true;
    }
  LogPrint (eLogWarning, "Packet: receiveStoreRequest: Unknown, ver: ",
            unsigned (packet->ver), ", type: ", packet->type);
  return false;
}

bool
IncomingRequest::receiveEmailPacketDeleteRequest (const sp_comm_pac &packet)
{
  LogPrint (eLogDebug, "Packet: receiveEmailPacketDeleteRequest");
  if (packet->ver == 4 && packet->type == type::CommD)
    {
      pbote::kademlia::DHT_worker.receiveEmailPacketDeleteRequest (packet);
      return true;
    }
  LogPrint (eLogWarning,
            "Packet: receiveEmailPacketDeleteRequest: Unknown, ver: ",
            unsigned (packet->ver), ", type: ", packet->type);
  return false;
}

bool
IncomingRequest::receiveIndexPacketDeleteRequest (const sp_comm_pac &packet)
{
  LogPrint (eLogDebug, "Packet: receiveIndexPacketDeleteRequest");
  if (packet->ver == 4 && packet->type == type::CommX)
    {
      pbote::kademlia::DHT_worker.receiveIndexPacketDeleteRequest (packet);
      return true;
    }
  LogPrint (eLogWarning,
            "Packet: receiveIndexPacketDeleteRequest: Unknown, ver: ",
            unsigned (packet->ver), ", type: ", packet->type);
  return false;
}

bool
IncomingRequest::receiveFindClosePeersRequest (const sp_comm_pac &packet)
{
  LogPrint (eLogDebug, "Packet: receiveFindClosePeersRequest");
  if ((packet->ver == 4 || packet->ver == 5) && packet->type == type::CommF)
    {
      pbote::kademlia::DHT_worker.receiveFindClosePeers (packet);
      return true;
    }

  LogPrint (eLogWarning,
            "Packet: receiveFindClosePeersRequest: Unknown, ver: ",
            unsigned (packet->ver), ", type: ", packet->type);
  return false;
}

RequestHandler::RequestHandler ()
    : started_ (false), m_PHandlerThread (nullptr), m_recvQueue (nullptr)
{
}

RequestHandler::~RequestHandler ()
{
  stop ();

  m_PHandlerThread->join ();
  delete m_PHandlerThread;
  m_PHandlerThread = nullptr;
}

void
RequestHandler::start ()
{
  if (!started_)
    {
      m_recvQueue = context.getRecvQueue ();
      m_sendQueue = context.getSendQueue ();
      started_ = true;
      m_PHandlerThread
          = new std::thread (std::bind (&RequestHandler::run, this));
    }
}

void
RequestHandler::stop ()
{
  if (started_)
    started_ = false;

  LogPrint (eLogInfo, "RequestHandler: Stopped");
}

void
RequestHandler::run ()
{
  LogPrint (eLogInfo, "PacketHandler: Started");
  while (started_)
    {
      auto queuePacket =
        m_recvQueue->GetNextWithTimeout (PACKET_RECEIVE_TIMEOUT);

      if (!queuePacket)
        continue;

      IncomingRequest newSession;

      if (!newSession.handleNewPacket (queuePacket))
        {
          LogPrint (eLogWarning, "PacketHandler: Parsing failed");

          pbote::ResponsePacket response;
          response.status = pbote::StatusCode::INVALID_PACKET;
          response.length = 0;
          auto data = response.toByte ();

          m_sendQueue->Put (std::make_shared<PacketForQueue> (
              queuePacket->destination, data.data (), data.size ()));
        }
    }
}

} // namespace packet
} // namespace pbote
