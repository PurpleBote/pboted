/**
 * Copyright (c) 2019-2020 polistern
 */

#ifndef PBOTE_PACKET_H__
#define PBOTE_PACKET_H__

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "Log.h"

#include "lib/libi2pd/Tag.h"

namespace pbote {

const std::array<std::uint8_t, 12> PACKET_TYPE{0x52, 0x4b, 0x46, 0x4e, 0x41, 0x51, 0x4c, 0x53, 0x44, 0x58, 0x43};
const std::array<std::uint8_t, 4> COMM_PREFIX{0x6D, 0x30, 0x52, 0xE9};
const std::array<std::uint8_t, 5> BOTE_VERSION{0x1, 0x2, 0x3, 0x4, 0x5};

/// 38 cause prefix[4] + type[1] + ver[1] +  cid[32]
const size_t COMM_DATA_LEN = 38;

enum StatusCode {
  OK,
  GENERAL_ERROR,
  NO_DATA_FOUND,
  INVALID_PACKET,
  INVALID_HASHCASH,
  INSUFFICIENT_HASHCASH,
  NO_DISK_SPACE
};

enum version {
  V1 = 0x01,
  V2 = 0x02,
  V3 = 0x03,
  V4 = 0x04,
  V5 = 0x05
};

enum type : uint8_t {
  /// Data Packets
  DataE = 0x45, // encrypted email Packet
  DataU = 0x55, // unencrypted email Packet
  DataI = 0x49, // index Packet
  DataT = 0x54, // deletion info Packet
  DataL = 0x4c, //DataP = 0x50, // peer list
  DataC = 0x43, // directory entry
  /// Communication Packets
  CommR = 0x52, // relay request
  CommK = 0x4b, // relay return request
  // CommF = 0x46, // fetch request
  CommN = 0x4e, // response Packet
  CommA = 0x41, // peer list request
  /// DHT Communication Packets
  CommQ = 0x51, // retrieve request
  CommY = 0x59, // CommL = 0x4c, // deletion query
  CommS = 0x53, // store request
  CommD = 0x44, // email Packet delete request
  CommX = 0x58, // index Packet delete request
  CommF = 0x46, // CommC = 0x43, // find close peers
};

struct PacketForQueue {
  PacketForQueue(std::string destination, uint8_t * buf, size_t len)
      : destination(std::move(destination)), payload(buf, buf + len) {}
  std::string destination;
  std::vector<uint8_t> payload;
};

template <typename T>
struct PacketBatch {
  std::map<std::vector<uint8_t>, PacketForQueue> outgoingPackets;
  std::map<std::string, T> incomingPackets;
  std::mutex m_batchMutex;
  std::condition_variable m_first, m_last;
  std::string owner;

  bool operator== (const PacketBatch& other) const {
    return outgoingPackets.size() == other.outgoingPackets.size() &&
    incomingPackets.size() == other.incomingPackets.size() &&
    std::equal(outgoingPackets.begin(), outgoingPackets.end(), other.outgoingPackets.begin()) &&
    std::equal(incomingPackets.begin(), incomingPackets.end(), other.incomingPackets.begin());
  }

  std::map<std::vector<uint8_t>, PacketForQueue> getPackets() { return outgoingPackets; }

  std::map<std::string, T> getResponses() { return incomingPackets; }

  bool contains(const std::vector<uint8_t>& id) {
    return outgoingPackets.find(id) != outgoingPackets.end();
  }

  size_t packetCount() { return outgoingPackets.size(); }

  size_t responseCount() { return incomingPackets.size(); }

  void addPacket(const std::vector<uint8_t>& id, const PacketForQueue& packet) {
    //i2p::data::Tag<32> cid(id.data());
    //LogPrint(eLogDebug, "PacketBatch: addPacket: owner: ", owner,", packet.cid: ", cid.ToBase64());
    outgoingPackets.insert(std::pair<std::vector<uint8_t>, PacketForQueue>(id, packet));
  }

  void addResponse(std::string peer, T packet) {
    incomingPackets.insert(std::pair<std::string, T>(peer, packet));
    if (incomingPackets.size() == 1)
      m_first.notify_one();
    if (incomingPackets.size() == outgoingPackets.size())
      m_last.notify_one();
  }

  bool waitFist(long timeout_sec) {
    std::chrono::duration<long> timeout = std::chrono::seconds(timeout_sec);
    std::unique_lock<std::mutex> l(m_batchMutex);
    m_first.wait_for(l, timeout);
    return true;
  }

  bool waitLast(long timeout_sec) {
    std::chrono::duration<long> timeout = std::chrono::seconds(timeout_sec);
    std::unique_lock<std::mutex> l(m_batchMutex);
    m_last.wait_for(l, timeout);
    return true;
  }
};

/// Packets
/// ToDo: toByte() method for packets with vectors
/// Data packets
struct DataPacket {
 public:
  DataPacket(uint8_t type_) : type(type_), ver(version::V4) {}
  uint8_t type;
  uint8_t ver;
};

struct EmailEncryptedPacket : public DataPacket{
 public:
  EmailEncryptedPacket() : DataPacket(DataE) {}
  uint8_t key[32];
  uint32_t stored_time;
  uint8_t delete_hash[32];
  uint8_t alg;
  uint16_t length;
  std::vector<uint8_t> edata;

  std::vector<uint8_t> toByte() {
    // Basic part
    std::vector<uint8_t> result;
    result.push_back(type);
    result.push_back(ver);

    result.insert(result.end(), std::begin(key), std::end(key));
    result.reserve(71 + edata.size());

    uint8_t v_time[4] = { static_cast<uint8_t>(stored_time >> 24), static_cast<uint8_t>(stored_time >> 16),
                          static_cast<uint8_t>(stored_time >>  8), static_cast<uint8_t>(stored_time & 0xffff) };
    result.insert(result.end(), std::begin(v_time), std::end(v_time));
    result.insert(result.end(), std::begin(delete_hash), std::end(delete_hash));

    result.push_back(alg);

    uint8_t v_length[2] = { static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length & 0xff) };
    result.insert(result.end(), std::begin(v_length), std::end(v_length));
    result.insert(result.end(), edata.begin(), edata.end());

    return result;
  }
};

struct EmailUnencryptedPacket : public DataPacket{
 public:
  EmailUnencryptedPacket() : DataPacket(DataU), fr_id(0), fr_count(0), length(0) {}
  uint8_t mes_id[32];
  uint8_t DA[32];
  uint16_t fr_id;
  uint16_t fr_count;
  uint16_t length;
  std::vector<uint8_t> data;

  std::vector<uint8_t> toByte() {
    // Basic part
    std::vector<uint8_t> result;
    result.reserve(72 + data.size());

    result.push_back(type);
    result.push_back(ver);

    result.insert(result.end(), std::begin(mes_id), std::end(mes_id));
    result.insert(result.end(), std::begin(DA), std::end(DA));

    uint8_t v_fr_id[2] = { static_cast<uint8_t>(fr_id >> 8), static_cast<uint8_t>(fr_id & 0xff) };
    result.insert(result.end(), std::begin(v_fr_id), std::end(v_fr_id));

    uint8_t v_fr_count[2] = { static_cast<uint8_t>(fr_count >> 8), static_cast<uint8_t>(fr_count & 0xff) };
    result.insert(result.end(), std::begin(v_fr_count), std::end(v_fr_count));

    uint8_t v_length[2] = { static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length & 0xff) };
    result.insert(result.end(), std::begin(v_length), std::end(v_length));
    result.insert(result.end(), data.begin(), data.end());

    return result;
  }
};

struct IndexPacket : public DataPacket{
 public:
  IndexPacket() : DataPacket(DataI), nump(0) {}
  struct Entry {
    uint8_t key[32];
    uint8_t dv[32];
    long time;
  };

  uint8_t hash[32] = {};
  uint32_t nump;
  std::vector<Entry> data;

  std::vector<uint8_t> toByte() {
    // Basic part
    std::vector<uint8_t> result;
    result.push_back(type);
    result.push_back(ver);

    result.insert(result.end(), std::begin(hash), std::end(hash));

    nump = htonl(nump);
    uint8_t v_nump[4];
    memcpy(v_nump, &nump, 4);
    result.insert(result.end(), std::begin(v_nump), std::end(v_nump));

    for (auto entry : data) {
      uint8_t arr[68];
      memcpy(arr, entry.key, 68);
      result.insert(result.end(), std::begin(arr), std::end(arr));
    }

    return result;
  }
};

struct DeletionInfoPacket : public DataPacket{
 public:
  DeletionInfoPacket() : DataPacket(DataT), count(0) {}
  struct item {
    uint8_t key[32];
    uint8_t da[32];
    uint32_t time;
  };

  uint32_t count;
  std::vector<item> data;

  std::vector<uint8_t> toByte() {
    return {};
  }
};

struct PeerListPacketV4 : public DataPacket{
 public:
  PeerListPacketV4() : DataPacket(DataL), count(0) {}
  uint16_t count;
  std::vector<uint8_t> data;

  std::vector<uint8_t> toByte() {
    // Basic part
    std::vector<uint8_t> result;
    result.push_back(type);
    result.push_back(ver);

    uint8_t v_count[2] = { static_cast<uint8_t>(count >> 8), static_cast<uint8_t>(count & 0xff) };
    result.insert(result.end(), std::begin(v_count), std::end(v_count));
    result.insert(result.end(), data.begin(), data.end());
    return result;
  }
};

struct PeerListPacketV5 : public DataPacket{
 public:
  PeerListPacketV5() : DataPacket(DataL), count(0) { ver = version::V5; }
  uint16_t count;
  std::vector<uint8_t> data;

  std::vector<uint8_t> toByte() {
    // Basic part
    std::vector<uint8_t> result;
    result.push_back(type);
    result.push_back(ver);

    uint8_t v_count[2] = { static_cast<uint8_t>(count >> 8), static_cast<uint8_t>(count & 0xff) };
    result.insert(result.end(), std::begin(v_count), std::end(v_count));
    result.insert(result.end(), data.begin(), data.end());
    return result;
  }
};

struct DirectoryEntryPacket : public DataPacket{
 public:
  DirectoryEntryPacket() : DataPacket(DataC) {}
  uint8_t key[32];
  uint16_t dest_length;
  std::vector<uint8_t> dest_data;
  uint32_t salt;
  uint16_t pic_length;
  std::vector<uint32_t> pic;
  uint8_t compress;
  uint16_t text_length;
  std::vector<uint8_t> text;

  std::vector<uint8_t> toByte() {
    return {};
  }
};

/// Communication packets

struct CommunicationPacket {
 public:
  CommunicationPacket(uint8_t type_) : prefix{0x6D, 0x30, 0x52, 0xE9}, type(type_), ver(version::V4) {}
  uint8_t prefix[4];
  uint8_t type;
  uint8_t ver;
  uint8_t cid[32];
  std::string from;
  std::vector<uint8_t> payload;
};

struct CleanCommunicationPacket {
 public:
  CleanCommunicationPacket(uint8_t type_) : prefix{0x6D, 0x30, 0x52, 0xE9}, type(type_), ver(version::V4) {}
  uint8_t prefix[4];
  uint8_t type;
  uint8_t ver;
  uint8_t cid[32];
};

struct RelayRequestPacket : public CleanCommunicationPacket{
 public:
  RelayRequestPacket() : CleanCommunicationPacket(CommR) {}
};

/// not implemented
/*struct RelayReturnRequestPacket : public CleanCommunicationPacket{
 public:
  RelayReturnRequestPacket() : CleanCommunicationPacket(CommK) {}
};*/

/// not implemented
/*struct FetchRequestPacket : public CleanCommunicationPacket{
 public:
  FetchRequestPacket() : CleanCommunicationPacket(CommF) {}
};*/

struct ResponsePacket : public CleanCommunicationPacket{
 public:
  ResponsePacket() : CleanCommunicationPacket(CommN) {}
  StatusCode status;
  uint16_t length;
  // 'I' = Index Packet
  // 'C' = Directory Entry
  // 'E' = Email Packet
  std::vector<uint8_t> data;

  std::vector<uint8_t> toByte() {
    // Basic part
    std::vector<uint8_t> result(std::begin(prefix), std::end(prefix));
    result.push_back(type);
    result.push_back(ver);
    result.insert(result.end(), std::begin(cid), std::end(cid));

    result.push_back(status);

    if (length > 0) {
      uint8_t v_length[2] = {static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length & 0xff)};
      result.insert(result.end(), std::begin(v_length), std::end(v_length));

      result.insert(result.end(), data.begin(), data.end());
    } else {
      uint8_t v_length[2] = {static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length & 0xff)};
      result.insert(result.end(), std::begin(v_length), std::end(v_length));
    }

    return result;
  }
};

struct PeerListRequestPacket : public CleanCommunicationPacket{
 public:
  PeerListRequestPacket() : CleanCommunicationPacket(CommA) {}
};

/// DHT packets

struct RetrieveRequestPacket : public CleanCommunicationPacket{
 public:
  RetrieveRequestPacket() : CleanCommunicationPacket(CommQ) {}
  uint8_t data_type;
  uint8_t key[32];
};

struct DeletionQueryPacket : public CleanCommunicationPacket{
 public:
  DeletionQueryPacket() : CleanCommunicationPacket(CommY) {}
  i2p::data::Tag<32> dht_key;
};

struct StoreRequestPacket : public CleanCommunicationPacket{
 public:
  StoreRequestPacket() : CleanCommunicationPacket(CommS) {}
  uint16_t hc_length;
  std::vector<uint8_t> hashcash;
  uint16_t length;
  std::vector<uint8_t> data;

  std::vector<uint8_t> toByte() {
    // Basic part
    std::vector<uint8_t> result(std::begin(prefix), std::end(prefix));
    result.push_back(type);
    result.push_back(ver);
    result.insert(result.end(), std::begin(cid), std::end(cid));

    uint8_t v_hc_length[2] = { static_cast<uint8_t>(hc_length >> 8), static_cast<uint8_t>(hc_length & 0xff) };
    result.insert(result.end(), std::begin(v_hc_length), std::end(v_hc_length));
    result.insert(result.end(), hashcash.begin(), hashcash.end());

    uint8_t v_length[2] = { static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length & 0xff) };

    result.insert(result.end(), std::begin(v_length), std::end(v_length));
    result.insert(result.end(), data.begin(), data.end());

    return result;
  }
};

struct EmailDeleteRequestPacket : public CleanCommunicationPacket{
 public:
  EmailDeleteRequestPacket() : CleanCommunicationPacket(CommD) {}
  uint8_t key[32];
  uint8_t DA[32];
};

struct IndexDeleteRequestPacket : public CleanCommunicationPacket{
 public:
  IndexDeleteRequestPacket() : CleanCommunicationPacket(CommX) {}
  /// not implemented
};

struct FindClosePeersRequestPacket : public CleanCommunicationPacket{
 public:
  FindClosePeersRequestPacket() : CleanCommunicationPacket(CommF) {}
  uint8_t key[32];
};

inline std::string statusToString(uint8_t status_code) {
  if (status_code == StatusCode::OK)
    return {"OK"};
  if (status_code == StatusCode::GENERAL_ERROR)
    return {"GENERAL ERROR"};
  if (status_code == StatusCode::NO_DATA_FOUND)
    return {"NO DATA FOUND"};
  if (status_code == StatusCode::INVALID_PACKET)
    return {"INVALID PACKET"};
  if (status_code == StatusCode::INVALID_HASHCASH)
    return {"INVALID HASHCASH"};
  if (status_code == StatusCode::INSUFFICIENT_HASHCASH)
    return {"INSUFFICIENT HASHCASH"};
  if (status_code == StatusCode::NO_DISK_SPACE)
    return {"NO DISK SPACE"};
  return {"UNKNOWN STATUS"};
}

inline std::string ToHex(const std::string &s, bool upper_case) {
  std::ostringstream ret;

  for (char i : s)
    ret << std::hex << std::setfill('0') << std::setw(2) << (upper_case ? std::uppercase : std::nouppercase) << (int) i;

  return ret.str();
}

inline std::shared_ptr<CommunicationPacket> parseCommPacket(const std::shared_ptr<PacketForQueue> &packet) {
  if (!packet->payload.empty()) {
    std::array<std::uint8_t, 4> payloadPrefix = {};

    if (packet->payload.size() > 4)
      payloadPrefix = {packet->payload[0], packet->payload[1], packet->payload[2], packet->payload[3]};

    if (payloadPrefix != COMM_PREFIX) {
      LogPrint(eLogWarning, "Packet: bad prefix");
      return nullptr;
    }

    /// just for init empty packet for memcpy
    CleanCommunicationPacket data(CommA);
    memcpy(&data, packet->payload.data(), COMM_DATA_LEN);

    bool goodType = std::find(std::begin(PACKET_TYPE), std::end(PACKET_TYPE), data.type) != std::end(PACKET_TYPE);
    if (!goodType) {
      LogPrint(eLogWarning, "Packet: bad type");
      return nullptr;
    }

    bool goodVersion = std::find(std::begin(BOTE_VERSION), std::end(BOTE_VERSION), data.ver) != std::end(BOTE_VERSION);
    if (!goodVersion) {
      LogPrint(eLogWarning, "Packet: bad version");
      return nullptr;
    }

    /// 38 cause prefix[4] + type[1] + ver[1] +  cid[32]
    long clean_payload_size = packet->payload.size() - 38;
    if (clean_payload_size < 0) {
      LogPrint(eLogWarning, "Packet: payload too short");
      return nullptr;
    }

    CommunicationPacket res(data.type);
    res.ver = data.ver;
    //for (int i = 0; i < 32; i++)
    //  res.cid[i] = data.cid[i];
    memcpy(res.cid, data.cid, 32);

    res.from = std::move(packet->destination);
    std::vector<uint8_t> v_payload(packet->payload.begin() + packet->payload.size() - clean_payload_size, packet->payload.end());
    res.payload = v_payload;

    return std::make_shared<CommunicationPacket>(res);

  } else {
    LogPrint(eLogWarning, "Packet: have no payload");
    return nullptr;
  }
}

} // namespace pbote

#endif // PBOTE_PACKET_H__
