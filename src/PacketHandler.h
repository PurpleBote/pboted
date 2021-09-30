/**
 * Copyright (c) 2019-2020 polistern
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

typedef bool (IncomingRequest::*incomingPacketHandler)(std::shared_ptr<pbote::CommunicationPacket> packet);

typedef bool (OutgoingRequest::*outgoingPacketHandler)(std::shared_ptr<pbote::CommunicationPacket> packet);

class IncomingRequest {
 public:
  IncomingRequest(RequestHandler &parent);
  ~IncomingRequest();

  bool handleNewPacket(const std::shared_ptr<PacketForQueue>& packet);

  /**
   * Handlers
   */
  bool receiveRelayRequest(std::shared_ptr<pbote::CommunicationPacket> packet);
  //bool receiveRelayReturnRequest(std::shared_ptr<pbote::CommunicationPacket> packet);
  //bool receiveFetchRequest(std::shared_ptr<pbote::CommunicationPacket> packet);
  bool receiveResponsePkt(std::shared_ptr<pbote::CommunicationPacket> packet);
  bool receivePeerListRequest(std::shared_ptr<pbote::CommunicationPacket> packet);
  ///
  bool receiveRetrieveRequest(std::shared_ptr<pbote::CommunicationPacket> packet);
  bool receiveDeletionQueryRequest(std::shared_ptr<pbote::CommunicationPacket> packet);
  bool receiveStoreRequest(std::shared_ptr<pbote::CommunicationPacket> packet);
  bool receiveEmailPacketDeleteRequest(std::shared_ptr<pbote::CommunicationPacket> packet);
  bool receiveIndexPacketDeleteRequest(std::shared_ptr<pbote::CommunicationPacket> packet);
  bool receiveFindClosePeersRequest(std::shared_ptr<pbote::CommunicationPacket> packet);
  /**
   * Parsers
   */
  bool parseEmailEncryptedPkt(std::shared_ptr<pbote::CommunicationPacket> packet);
  bool parseEmailUnencryptedPkt(std::shared_ptr<pbote::CommunicationPacket> packet);
  //bool parseIndexPkt(unsigned char* buf, size_t len);
  bool parseDeletionInfoPkt(std::shared_ptr<pbote::CommunicationPacket> packet);
  //bool parsePeerListPkt(const unsigned char* buf, size_t len);
  bool parseContactPkt(std::shared_ptr<pbote::CommunicationPacket> packet);
  bool parseChainPkt(std::shared_ptr<pbote::CommunicationPacket> packet);
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

  bool isRunning();

 private:
  void processPacket();
  void run();

  bool started_;
  std::thread *m_PHandlerThread;
  pbote::util::Queue<std::shared_ptr<PacketForQueue>> *m_recvQueue;
  pbote::util::Queue<std::shared_ptr<PacketForQueue>> *m_sendQueue;
};

extern RequestHandler handler;

} // namespace packet
} // namespace pbote

#endif // PACKET_HANDLER_H__