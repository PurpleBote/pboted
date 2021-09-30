/**
 * Copyright (c) 2019-2020 polistern
 */

#include <utility>
#include <random>

#include "DHTworker.h"
#include "PacketHandler.h"
#include "RelayPeersWorker.h"

namespace pbote {
namespace packet {

RequestHandler handler;

//uint8_t PacketType[] = {0x45, 0x55, 0x49, 0x54, 0x50, 0x43, 0x52, 0x4b, 0x46, 0x4e, 0x41, 0x51, 0x4c, 0x53, 0x44, 0x58, 0x43};

//uint8_t CommunicationPreffix[] = {0x6D, 0x30, 0x52, 0xE9};

IncomingRequest::IncomingRequest(RequestHandler &parent)
    : m_Parent(parent) {
  // ToDo: re-make with std::function
  incomingPacketHandlers_[type::CommR] = &IncomingRequest::receiveRelayRequest;
  //incomingPacketHandlers_[type::CommK] = &IncomingRequest::receiveRelayReturnRequest;
  //incomingPacketHandlers_[type::CommF] = &IncomingRequest::receiveFetchRequest;
  incomingPacketHandlers_[type::CommN] = &IncomingRequest::receiveResponsePkt;
  incomingPacketHandlers_[type::CommA] = &IncomingRequest::receivePeerListRequest;

  incomingPacketHandlers_[type::CommQ] = &IncomingRequest::receiveRetrieveRequest;
  incomingPacketHandlers_[type::CommY] = &IncomingRequest::receiveDeletionQueryRequest;
  incomingPacketHandlers_[type::CommS] = &IncomingRequest::receiveStoreRequest;
  incomingPacketHandlers_[type::CommD] = &IncomingRequest::receiveEmailPacketDeleteRequest;
  incomingPacketHandlers_[type::CommX] = &IncomingRequest::receiveIndexPacketDeleteRequest;
  incomingPacketHandlers_[type::CommF] = &IncomingRequest::receiveFindClosePeersRequest;
}

IncomingRequest::~IncomingRequest() {}

bool IncomingRequest::handleNewPacket(const std::shared_ptr<PacketForQueue>& queuePacket) {
  auto packet = pbote::parseCommPacket(queuePacket);
  if (packet != nullptr) {
    /// First we need to check CID in batches
    if (context.receive(packet->from, *packet)) {
      //LogPrint(eLogDebug, "PacketHandler: packet ", packet->type, " pass to batch");
      return true;
    }

    auto it = incomingPacketHandlers_.find(packet->type);
    LogPrint(eLogDebug, "PacketHandler: it is ", it->first, "::", it->second);

    if (it != incomingPacketHandlers_.end())
      return (this->*(it->second))(packet);
    else {
      LogPrint(eLogWarning, "PacketHandler: got unknown packet type");
      return false;
    }

  } else {
    LogPrint(eLogWarning, "PacketHandler: can't parse packet");
    return false;
  }
}

///////////////////////////////////////////////////////////////////////////////////////////
/// HANDLERS START
///////////////////////////////////////////////////////////////////////////////////////////

bool IncomingRequest::receiveRelayRequest(std::shared_ptr<pbote::CommunicationPacket> packet) {
  LogPrint(eLogDebug, "PacketHandler: start receiveRelayRequest");
  /*uint16_t offset = 0;

  uint8_t cid[32];
  uint16_t hashCashLen;
  uint32_t delay;
  uint8_t nextDest[384];
  // uint8_t chainPkt = createChainPkt();

  uint8_t hashCah;*/

  return true;
}

/**
 * not implemented
 */
/*bool IncomingRequest::receiveRelayReturnRequest(std::shared_ptr<pbote::CommunicationPacket> packet) {
  LogPrint(eLogDebug, "PacketHandler: start receiveRelayReturnRequest");
  return true;
}*/

/**
 * not implemented
 */
/*bool IncomingRequest::receiveFetchRequest(std::shared_ptr<pbote::CommunicationPacket> packet) {
  LogPrint(eLogDebug, "PacketHandler: start receiveFetchRequest");
  uint16_t offset = 0;

  uint8_t cid[32];
  uint8_t dataType;
  uint8_t key[32];
  uint8_t emailKeyPair[384];
  uint16_t retLen;

  std::memcpy(&cid, packet->payload(), 32);
  offset += 32;
  std::memcpy(&dataType, packet->payload() + offset, 1);
  offset += 1;
  std::memcpy(&key, packet->payload() + offset, 32);
  offset += 32;
  std::memcpy(&emailKeyPair, packet->payload() + offset, 384);
  offset += 384;
  std::memcpy(&retLen, packet->payload() + offset, 2);
  offset += 2;

  uint8_t ret[(int)retLen];

  std::memcpy(&ret, packet->payload() + offset, retLen);
  offset += retLen;
  return true;
}*/

bool IncomingRequest::receiveResponsePkt(std::shared_ptr<pbote::CommunicationPacket> packet) {
  size_t offset = 0;
  unsigned char status;
  uint16_t dataLen;

  std::memcpy(&status, packet->payload.data(), sizeof status); offset += 1;
  std::memcpy(&dataLen, packet->payload.data() + offset, sizeof dataLen); dataLen = ntohs(dataLen); offset += 2;

  if ((packet->payload.size() - offset) != dataLen)
    LogPrint(eLogWarning, "Packet: receiveResponsePkt: size mismatch: size=", (packet->payload.size() - offset), ", dataLen=", dataLen);

  uint8_t data[dataLen];
  std::memcpy(&data, packet->payload.data() + offset, dataLen);

  /// Peer List
  /// L for mhatta, P for str4d
  if (data[0] == (uint8_t)'L' || data[0] == (uint8_t)'P') {
    LogPrint(eLogInfo, "Packet: receiveResponsePkt: Peer List, data.type=", data[0], ", data.ver=", unsigned(data[1]));
    return pbote::relay::relay_peers_worker.packetReceived(data, dataLen);
  }

  /// Index Packet
  if (data[0] == (uint8_t)'I') {
    LogPrint(eLogInfo, "Packet: receiveResponsePkt: Index Packet");
    return true;
  }

  /// Email Packet
  if (data[0] == (uint8_t)'E') {
    LogPrint(eLogInfo, "Packet: receiveResponsePkt: Email Packet");
    return true;
  }

  /// Directory Entry Packet
  if (data[0] == (uint8_t)'C') {
    LogPrint(eLogInfo, "Packet: receiveResponsePkt: Directory Entry Packet");
    return true;
  }

  LogPrint(eLogWarning, "Packet: receiveResponsePkt: data.type=", data[0], ", data.ver=", unsigned(data[1]));
  LogPrint(eLogWarning, "Packet: receiveResponsePkt: unsupported data packet type");
  return false;
}

bool IncomingRequest::receivePeerListRequest(std::shared_ptr<pbote::CommunicationPacket> packet) {
  LogPrint(eLogDebug, "Packet: receivePeerListRequest");
  if (packet->ver == 4)
    pbote::relay::relay_peers_worker.peerListRequestV4(packet->from, packet->cid);
  else
    return false;
  return true;
}

///////////////////////////////////////////////////////////////////////////////////////////

bool IncomingRequest::receiveRetrieveRequest(std::shared_ptr<pbote::CommunicationPacket> packet) {
  LogPrint(eLogDebug, "PacketHandler: start receiveRetrieveRequest");
  /*uint16_t offset = 0;

  uint8_t cid[32];
  uint8_t dataType;
  uint8_t key[32];*/

  /*std::memcpy(&cid, packet->payload(), 32);
  offset += 32;
  std::memcpy(&dataType, packet->payload() + offset, 1);
  offset += 1;
  std::memcpy(&key, packet->payload() + offset, 32);
  offset += 32;*/
  return true;
}

bool IncomingRequest::receiveDeletionQueryRequest(std::shared_ptr<pbote::CommunicationPacket> packet) {
  LogPrint(eLogDebug, "PacketHandler: start receiveDeletionQueryRequest");
  /*uint16_t offset = 0;

  uint8_t cid[32];
  uint8_t key[32];*/

  /*std::memcpy(&cid, packet->payload(), 32);
  offset += 32;
  std::memcpy(&key, packet->payload() + offset, 32);
  offset += 32;*/
  return true;
}

bool IncomingRequest::receiveStoreRequest(std::shared_ptr<pbote::CommunicationPacket> packet) {
  LogPrint(eLogDebug, "PacketHandler: start receiveStoreRequest");
  /*uint16_t offset = 0;

  uint8_t cid[32];
  uint16_t hashCashLen;*/

  /*std::memcpy(&cid, packet->payload(), 32);
  offset += 32;
  std::memcpy(&hashCashLen, packet->payload() + offset, 2);
  offset += 2;

  uint8_t hashCash[(int)hashCashLen];

  std::memcpy(&hashCash, packet->payload() + offset, hashCashLen);
  offset += hashCashLen;

  uint16_t dataLen;

  std::memcpy(&dataLen, packet->payload() + offset, 2);
  offset += 2;

  uint8_t data[(int)dataLen];

  std::memcpy(&data, packet->payload() + offset, dataLen);
  offset += dataLen;*/
  return true;
}

bool IncomingRequest::receiveEmailPacketDeleteRequest(std::shared_ptr<pbote::CommunicationPacket> packet) {
  LogPrint(eLogDebug, "PacketHandler: start receiveEmailPacketDeleteRequest");
  /*uint16_t offset = 0;

  uint8_t cid[32];
  uint8_t key[32];
  uint8_t delAuth[32];*/

  /*std::memcpy(&cid, packet->payload(), 32);
  offset += 32;
  std::memcpy(&key, packet->payload() + offset, 32);
  offset += 32;
  std::memcpy(&delAuth, packet->payload() + offset, 32);
  offset += 32;*/
  return true;
}

bool IncomingRequest::receiveIndexPacketDeleteRequest(std::shared_ptr<pbote::CommunicationPacket> packet) {
  LogPrint(eLogDebug, "PacketHandler: start receiveIndexPacketDeleteRequest");
  /*uint16_t offset = 0;

  uint8_t cid[32];
  uint8_t dh[32];
  uint8_t num;*/

  /*std::memcpy(&cid, packet->payload(), 32);
  offset += 32;
  std::memcpy(&dh, packet->payload() + offset, 32);
  offset += 32;
  std::memcpy(&num, packet->payload() + offset, 1);
  offset += 1;

  uint8_t dht[32];
  uint8_t delAuth[32];

  std::tuple<uint8_t *, uint8_t *> entries[(int)num];

  for (uint32_t i = 0; i < num; i--) {
    std::memcpy(&dht, packet->payload() + offset, 32);
    offset += 32;
    std::memcpy(&delAuth, packet->payload() + offset, 32);
    offset += 32;
    entries[i] = std::make_tuple(dht, delAuth);
  }*/
  return true;
}

bool IncomingRequest::receiveFindClosePeersRequest(std::shared_ptr<pbote::CommunicationPacket> packet) {
  LogPrint(eLogDebug, "PacketHandler: start receiveFindClosePeersRequest");
  /*uint16_t offset = 0;

  uint8_t cid[32];
  uint8_t key[32];*/

  /*std::memcpy(&cid, packet->payload(), 32);
  offset += 32;
  std::memcpy(&key, packet->payload() + offset, 32);
  offset += 32;*/
  return true;
}

///////////////////////////////////////////////////////////////////////////////////////////
/// HANDLERS END
///////////////////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////////////////
/// PARSERS START
///////////////////////////////////////////////////////////////////////////////////////////
bool IncomingRequest::parseEmailEncryptedPkt(std::shared_ptr<pbote::CommunicationPacket> packet) {
  LogPrint(eLogDebug, "PacketHandler: start handleEmailEncryptedPkt");
  /*uint16_t offset = 0;

  uint8_t *key[32];
  uint8_t *time[4];
  uint8_t *delHash[32];
  uint8_t *alg[1];
  uint8_t *dataLen[2];
  uint8_t *delKey[32];

  std::memcpy(key, packet->payload().c_str(), 32);
  offset += 32;
  std::memcpy(time, packet->payload().c_str() + offset, 4);
  offset += 4;
  std::memcpy(delHash, packet->payload().c_str() + offset, 32);
  offset += 32;
  std::memcpy(alg, packet->payload().c_str() + offset, 1);
  offset += 1;
  std::memcpy(dataLen, packet->payload().c_str() + offset, 2);
  offset += 2;
  std::memcpy(delKey, packet->payload().c_str() + offset, 32);
  offset += 32;

  uint8_t *data[dataLen[1]];

  std::memcpy(data, packet->payload() + offset, sizeof packet->payload() - offset);*/
  return true;
}

bool IncomingRequest::parseEmailUnencryptedPkt(std::shared_ptr<pbote::CommunicationPacket> packet) {
  LogPrint(eLogDebug, "PacketHandler: start handleEmailUnencryptedPkt");
  /*uint16_t offset = 0;

  uint8_t *messID[32];
  uint8_t *delKey[32];
  uint8_t *frID[2];
  uint8_t *frNum[2];
  uint8_t *dataLen[2];

  std::memcpy(messID, packet->payload(), 32);
  offset += 32;
  std::memcpy(delKey, packet->payload() + offset, 32);
  offset += 32;
  std::memcpy(frID, packet->payload() + offset, 2);
  offset += 2;
  std::memcpy(frNum, packet->payload() + offset, 2);
  offset += 2;
  std::memcpy(dataLen, packet->payload() + offset, 2);
  offset += 2;

  uint8_t *data[*dataLen];

  std::memcpy(data, packet->payload() + offset,
              sizeof packet->payload() - offset);*/
  return true;
}


/*bool IncomingRequest::parseIndexPkt(unsigned char* buf, size_t len) {
  LogPrint(eLogDebug, "PacketHandler: start handleIndexPkt");
  uint16_t offset = 0;

  uint8_t dh[32];
  uint8_t num[4];

  std::memcpy(&dh, buf, 32);
  offset += 32;
  std::memcpy(&num, buf + offset, 4);
  offset += 4;

  uint8_t key[32];
  uint8_t delHash[32];
  uint32_t time;

  std::tuple<uint8_t *, uint8_t *, uint32_t> entries[(int)num];

  for (uint32_t i = 0; i < num; i--) {
    std::memcpy(key, buf + offset, 32);
    offset += 32;
    std::memcpy(delHash, packet->payload() + offset, 32);
    offset += 32;
    std::memcpy(&time, packet->payload() + offset, 4);
    offset += 4;
    entries[i] = std::make_tuple(key, delHash, time);
  }
  return true;
}*/


bool IncomingRequest::parseDeletionInfoPkt(std::shared_ptr<pbote::CommunicationPacket> packet) {
  LogPrint(eLogDebug, "PacketHandler: start handleDeletionInfoPkt");
  /*uint16_t offset = 0;

  uint8_t num[4];

  std::memcpy(&num, packet->payload(), 4);
  offset += 4;

  uint8_t key[32];
  uint8_t delAuth[32];
  uint32_t time;

  std::tuple<uint8_t *, uint8_t *, uint32_t> entries[(int)num];

  for (uint32_t i = 0; i < num; i--) {
    std::memcpy(key, packet->payload() + offset, 32);
    offset += 32;
    std::memcpy(delAuth, packet->payload() + offset, 32);
    offset += 32;
    std::memcpy(&time, packet->payload() + offset, 4);
    offset += 4;
    entries[i] = std::make_tuple(key, delAuth, time);
  }*/
  return true;
}

bool IncomingRequest::parseContactPkt(std::shared_ptr<pbote::CommunicationPacket> packet) {
  LogPrint(eLogDebug, "PacketHandler: start handleContactPkt");
  /*uint16_t offset = 0;

  uint8_t key[32];
  uint16_t destLen;
  uint32_t salt;
  uint16_t pictLen;
  uint8_t textCompres;
  uint16_t textLen;

  std::memcpy(&key, packet->payload(), 32);
  offset += 32;
  std::memcpy(&destLen, packet->payload() + offset, 2);
  offset += 2;

  uint8_t dest[(int)destLen];

  std::memcpy(&dest, packet->payload() + offset, destLen);
  offset += destLen;
  std::memcpy(&salt, packet->payload() + offset, 4);
  offset += 4;
  std::memcpy(&pictLen, packet->payload() + offset, 2);
  offset += 2;

  uint8_t pict[(int)pictLen];

  std::memcpy(&pict, packet->payload() + offset, pictLen);
  offset += pictLen;
  std::memcpy(&textCompres, packet->payload() + offset, 1);
  offset += 1;
  std::memcpy(&textLen, packet->payload() + offset, 2);
  offset += 2;

  uint8_t text[(int)textLen];

  std::memcpy(&text, packet->payload() + offset, textLen);
  offset += textLen;*/
  return true;
}

bool IncomingRequest::parseChainPkt(std::shared_ptr<pbote::CommunicationPacket> packet) {
  LogPrint(eLogDebug, "PacketHandler: start parseChainPkt");
  return true;
}

///////////////////////////////////////////////////////////////////////////////////////////
/// PARSERS END
///////////////////////////////////////////////////////////////////////////////////////////

RequestHandler::RequestHandler()
    : started_(false), m_PHandlerThread(nullptr), m_recvQueue(nullptr),
      m_sendQueue(nullptr) {}

RequestHandler::~RequestHandler() {
  delete m_PHandlerThread;
  m_PHandlerThread = nullptr;
}

void RequestHandler::start() {
  if (!started_) {
    m_recvQueue = context.getRecvQueue();
    m_sendQueue = context.getSendQueue();
    started_ = true;
    m_PHandlerThread = new std::thread(std::bind(&RequestHandler::run, this));
  }
}

void RequestHandler::stop() {
  started_ = false;
  if (m_PHandlerThread) {
    m_PHandlerThread->join();
    delete m_PHandlerThread;
    m_PHandlerThread = nullptr;
  }
}

void RequestHandler::run() {
  LogPrint(eLogInfo, "PacketHandler: run packet handler thread");
  processPacket();
}

bool RequestHandler::isRunning() { return started_; }

void RequestHandler::processPacket() {
  while (started_) {
    auto queuePacket = m_recvQueue->GetNext();
    //LogPrint(eLogInfo, "PacketHandler: got new packet");
    //LogPrint(eLogInfo, "PacketHandler: queuePacket.sender=", queuePacket->destination);
    //LogPrint(eLogInfo, "PacketHandler: queuePacket.payload=", queuePacket->payload.substr(0, 8));
    IncomingRequest newSession(*this);
    bool isOk = newSession.handleNewPacket(queuePacket);

    if (!isOk)
      LogPrint(eLogWarning, "PacketHandler: parsing failed");

    //if (m_IsRunning)
      //processPacket();
  }
}

} // namespace packet
} // namespace pbote
