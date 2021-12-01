/**
 * Copyright (c) 2019-2021 polistern
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
#include <openssl/sha.h>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "Tag.h"

#include "Logging.h"

namespace pbote {

/// because prefix[4] + type[1] + ver[1] +  cid[32] = 38
#define COMM_DATA_LEN 38

const std::array<std::uint8_t, 12> PACKET_TYPE{0x52, 0x4b, 0x46, 0x4e, 0x41, 0x51, 0x4c, 0x53, 0x44, 0x58, 0x43};
const std::array<std::uint8_t, 4> COMM_PREFIX{0x6D, 0x30, 0x52, 0xE9};
const std::array<std::uint8_t, 5> BOTE_VERSION{0x1, 0x2, 0x3, 0x4, 0x5};

enum StatusCode {
  OK,
  GENERAL_ERROR,
  NO_DATA_FOUND,
  INVALID_PACKET,
  INVALID_HASHCASH,
  INSUFFICIENT_HASHCASH,
  NO_DISK_SPACE,
  DUPLICATED_DATA
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

inline std::string statusToString(uint8_t status_code) {
  switch (status_code) {
    case StatusCode::OK:
      return {"OK"};
    case StatusCode::GENERAL_ERROR:
      return {"GENERAL ERROR"};
    case StatusCode::NO_DATA_FOUND:
      return {"NO DATA FOUND"};
    case StatusCode::INVALID_PACKET:
      return {"INVALID PACKET"};
    case StatusCode::INVALID_HASHCASH:
      return {"INVALID HASHCASH"};
    case StatusCode::INSUFFICIENT_HASHCASH:
      return {"INSUFFICIENT HASHCASH"};
    case StatusCode::NO_DISK_SPACE:
      return {"NO DISK SPACE"};
    case StatusCode::DUPLICATED_DATA:
      return {"DUPLICATED DATA"};
    default:
      return {"UNKNOWN STATUS"};
  }
}

struct PacketForQueue {
  PacketForQueue(std::string destination, uint8_t * buf, size_t len)
      : destination(std::move(destination)), payload(buf, buf + len) {}
  std::string destination;
  std::vector<uint8_t> payload;
};

template <typename T>
struct PacketBatch {
  std::map<std::vector<uint8_t>, PacketForQueue> outgoingPackets;
  std::vector<std::shared_ptr<T>> incomingPackets;
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

  std::vector<std::shared_ptr<T>> getResponses() { return incomingPackets; }

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

  void removePacket(const std::vector<uint8_t>& cid) { outgoingPackets.erase(cid); }

  void addResponse(std::shared_ptr<T> packet) {
    incomingPackets.push_back(packet);
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
/// Data packets
struct DataPacket {
 public:
  explicit DataPacket(uint8_t type_) : type(type_), ver(version::V4) {}
  uint8_t type;
  uint8_t ver;
};

struct EmailEncryptedPacket : public DataPacket{
 public:
  EmailEncryptedPacket() : DataPacket(DataE) {}

  uint8_t key[32]{};
  int32_t stored_time{};
  uint8_t delete_hash[32]{};
  uint8_t alg{};
  uint16_t length{};
  std::vector<uint8_t> edata;

  bool fromBuffer(uint8_t *buf, size_t len, bool from_net) {
    /// 105 cause type[1] + ver[1] + key[32] + stored_time[4] + delete_hash[32] + alg[1] + length[2] + DA[32]
    if (len < 105) {
      LogPrint(eLogWarning, "Packet: EmailEncryptedPacket: fromBuffer: payload is too short: ", len);
      return {};
    }

    size_t offset = 0;

    std::memcpy(&type, buf, 1);
    offset += 1;
    std::memcpy(&ver, buf + offset, 1);
    offset += 1;

    if (type != (uint8_t) 'E') {
      LogPrint(eLogWarning, "Packet: EmailEncryptedPacket: fromBuffer: wrong packet type: ", type);
      return false;
    }

    if (ver != (uint8_t) 4) {
      LogPrint(eLogWarning, "Packet: EmailEncryptedPacket: fromBuffer: wrong packet version: ", unsigned(ver));
      return false;
    }

    std::memcpy(&key, buf + offset, 32);
    offset += 32;
    std::memcpy(&stored_time, buf + offset, 4);
    offset += 4;
    std::memcpy(&delete_hash, buf + offset, 32);
    offset += 32;
    std::memcpy(&alg, buf + offset, 1);
    offset += 1;

    std::vector<uint8_t> data_for_verify(buf + offset, buf + len);

    std::memcpy(&length, buf + offset, 2);
    offset += 2;

    if (from_net) {
      stored_time = (int32_t)ntohl((uint32_t)stored_time);
      length = ntohs(length);
    }

    LogPrint(eLogDebug, "Packet: EmailEncryptedPacket: fromBuffer: packet.stored_time: ", stored_time);
    LogPrint(eLogDebug, "Packet: EmailEncryptedPacket: fromBuffer: packet.alg: ", unsigned(alg));
    LogPrint(eLogDebug, "Packet: EmailEncryptedPacket: fromBuffer: packet.length: ", length);

    i2p::data::Tag<32> ver_hash(key);
    uint8_t data_hash[32];
    SHA256(data_for_verify.data(), data_for_verify.size(), data_hash);
    i2p::data::Tag<32> cur_hash(data_hash);

    LogPrint(eLogDebug, "Packet: EmailEncryptedPacket: fromBuffer: ver_hash: ", ver_hash.ToBase64());
    LogPrint(eLogDebug, "Packet: EmailEncryptedPacket: fromBuffer: cur_hash: ", cur_hash.ToBase64());

    if (ver_hash != cur_hash) {
      LogPrint(eLogError, "Packet: EmailEncryptedPacket: fromBuffer: hash mismatch");
      return false;
    }

    LogPrint(eLogDebug, "Packet: EmailEncryptedPacket: fromBuffer: alg: ", unsigned(alg), ", length: ", length);
    std::vector<uint8_t> data(buf + offset, buf + offset + length);
    edata = data;
    return true;
  }

  std::vector<uint8_t> toByte() {
    /// Start basic part
    std::vector<uint8_t> result;
    result.reserve(71 + edata.size());

    result.push_back(type);
    result.push_back(ver);
    /// End basic part

    result.insert(result.end(), std::begin(key), std::end(key));

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
  uint8_t mes_id[32]{};
  uint8_t DA[32]{};
  uint16_t fr_id;
  uint16_t fr_count;
  uint16_t length;
  std::vector<uint8_t> data;

  std::vector<uint8_t> toByte() {
    /// Start basic part
    std::vector<uint8_t> result;
    result.reserve(72 + data.size());

    result.push_back(type);
    result.push_back(ver);
    /// End basic part

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
    int32_t time;
  };

  uint8_t hash[32]{};
  uint32_t nump;
  std::vector<Entry> data;

  bool fromBuffer(const std::vector<uint8_t> &buf, bool from_net) {
    /// because type[1] + ver[1] + DH[32] + nump[4] == 38 byte
    if (buf.size() < 38) {
      LogPrint(eLogWarning, "Packet: IndexPacket: fromBuffer: payload is too short");
      return false;
    }
    uint16_t offset = 0;

    std::memcpy(&type, buf.data(), 1);
    offset += 1;
    std::memcpy(&ver, buf.data() + offset, 1);
    offset += 1;
    std::memcpy(&hash, buf.data() + offset, 32);
    offset += 32;

    std::memcpy(&nump, buf.data() + offset, 4);
    LogPrint(eLogDebug, "Packet: IndexPacket: fromBuffer: nump raw: ", nump, ", ntohl: ", ntohl(nump),
             ", from_net: ", from_net ? "true" : "false");
    if (from_net)
      nump = ntohl(nump);

    offset += 4;

    LogPrint(eLogDebug, "Packet: IndexPacket: fromBuffer: nump: ", nump, ", type: ", type,
             ", version: ", unsigned(ver));

    if (type != (uint8_t) 'I') {
      LogPrint(eLogWarning, "Packet: IndexPacket: fromBuffer: wrong packet type: ", type);
      return false;
    }

    if (ver != (uint8_t) 4) {
      LogPrint(eLogWarning, "Packet: IndexPacket: fromBuffer: wrong packet version: ", unsigned(ver));
      return false;
    }

    // Check if payload length enough to parse all entries
    if (buf.size() < (38 + (68 * nump))) {
      LogPrint(eLogWarning, "Packet: IndexPacket: fromBuffer: incomplete packet!");
      return false;
    }

    for (uint32_t i = 0; i < nump; i--) {
      pbote::IndexPacket::Entry entry = {};
      std::memcpy(&entry.key, buf.data() + offset, 32);
      offset += 32;
      i2p::data::Tag<32> key(entry.key);
      LogPrint(eLogDebug, "Packet: IndexPacket: fromBuffer: mail key: ", key.ToBase64());

      std::memcpy(&entry.dv, buf.data() + offset, 32);
      offset += 32;
      i2p::data::Tag<32> dv(entry.dv);
      LogPrint(eLogDebug, "Packet: IndexPacket: fromBuffer: mail dvr: ", dv.ToBase64());

      std::memcpy(&entry.time, buf.data() + offset, 4);
      offset += 4;
      data.push_back(entry);
    }
    return true;
  }

  std::vector<uint8_t> toByte() {
    /// Start basic part
    std::vector<uint8_t> result;
    result.reserve(38 + (data.size() * 68));

    result.push_back(type);
    result.push_back(ver);
    /// End basic part

    result.insert(result.end(), std::begin(hash), std::end(hash));

    uint8_t v_nump[4] = { static_cast<uint8_t>(nump >> 24), static_cast<uint8_t>(nump >> 16),
                          static_cast<uint8_t>(nump >>  8), static_cast<uint8_t>(nump & 0xffff) };

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
    long time;
  };

  uint32_t count;
  std::vector<item> data;

  std::vector<uint8_t> toByte() {
    /// Start basic part
    std::vector<uint8_t> result;
    result.reserve(6 + (data.size() * 68));

    result.push_back(type);
    result.push_back(ver);
    /// End basic part

    for (auto entry : data) {
      uint8_t arr[68];
      memcpy(arr, entry.key, 68);
      result.insert(result.end(), std::begin(arr), std::end(arr));
    }

    return result;
  }
};

struct PeerListPacketV4 : public DataPacket{
 public:
  PeerListPacketV4() : DataPacket(DataL), count(0) {}

  uint16_t count;
  std::vector<uint8_t> data;

  std::vector<uint8_t> toByte() {
    /// Start basic part
    std::vector<uint8_t> result;
    result.reserve(4 + data.size());

    result.push_back(type);
    result.push_back(ver);
    /// End basic part

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
    /// Start basic part
    std::vector<uint8_t> result;
    result.reserve(4 + data.size());

    result.push_back(type);
    result.push_back(ver);
    /// End basic part

    uint8_t v_count[2] = { static_cast<uint8_t>(count >> 8), static_cast<uint8_t>(count & 0xff) };
    result.insert(result.end(), std::begin(v_count), std::end(v_count));
    result.insert(result.end(), data.begin(), data.end());
    return result;
  }
};

struct DirectoryEntryPacket : public DataPacket{
 public:
  DirectoryEntryPacket() : DataPacket(DataC) {}

  uint8_t key[32]{};
  uint16_t dest_length{};
  std::vector<uint8_t> dest_data;
  uint32_t salt{};
  uint16_t pic_length{};
  std::vector<uint32_t> pic;
  uint8_t compress{};
  uint16_t text_length{};
  std::vector<uint8_t> text;

  std::vector<uint8_t> toByte() {
    /// Start basic part
    std::vector<uint8_t> result;
    result.reserve(4 );

    result.push_back(type);
    result.push_back(ver);
    /// End basic part

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
  uint8_t cid[32]{};
  std::string from;
  std::vector<uint8_t> payload;
};

struct CleanCommunicationPacket {
 public:
  CleanCommunicationPacket(uint8_t type_) : prefix{0x6D, 0x30, 0x52, 0xE9}, type(type_), ver(version::V4) {}

  uint8_t prefix[4];
  uint8_t type;
  uint8_t ver;
  uint8_t cid[32]{};
};

/// not implemented
/*struct RelayRequestPacket : public CleanCommunicationPacket{
 public:
  RelayRequestPacket() : CleanCommunicationPacket(CommR) {}
};*/

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

  StatusCode status{};
  uint16_t length{};
  // 'I' = Index Packet
  // 'C' = Directory Entry
  // 'E' = Email Packet
  // or empty with non-OK status
  std::vector<uint8_t> data;

  bool fromBuffer(uint8_t *buf, size_t len, bool from_net) {
    /// 3 cause status[1] + length[2]
    if (len < 3) {
      LogPrint(eLogWarning, "Packet: ResponsePacket: fromBuffer: payload is too short: ", len);
      return false;
    }

    size_t offset = 0;

    std::memcpy(&status, buf, 1);
    offset += 1;
    std::memcpy(&length, buf + offset, 2);
    offset += 2;

    if (from_net)
      length = ntohs(length);

    if (status != StatusCode::OK) {
      LogPrint(eLogWarning, "Packet: ResponsePacket: response status: ", statusToString(status));
      return true;
    }

    if (length == 0) {
      LogPrint(eLogWarning, "Packet: ResponsePacket: packet without payload, skip parsing");
      return true;
    }

    data = std::vector<uint8_t>(buf + offset, buf + offset + length);
    return true;
  }

  std::vector<uint8_t> toByte() {
    /// Start basic part
    std::vector<uint8_t> result(std::begin(prefix), std::end(prefix));
    result.push_back(type);
    result.push_back(ver);
    result.insert(result.end(), std::begin(cid), std::end(cid));
    /// End basic part

    result.push_back(status);

    uint8_t v_length[2] = {static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length & 0xff)};
    result.insert(result.end(), std::begin(v_length), std::end(v_length));

    if (length > 0)
      result.insert(result.end(), data.begin(), data.end());

    return result;
  }
};

struct PeerListRequestPacket : public CleanCommunicationPacket{
 public:
  PeerListRequestPacket() : CleanCommunicationPacket(CommA) {}

  std::vector<uint8_t> toByte() {
    /// Start basic part
    std::vector<uint8_t> result(std::begin(prefix), std::end(prefix));
    result.push_back(type);
    result.push_back(ver);
    result.insert(result.end(), std::begin(cid), std::end(cid));
    /// End basic part

    return result;
  }
};

/// DHT packets

struct RetrieveRequestPacket : public CleanCommunicationPacket{
 public:
  RetrieveRequestPacket() : CleanCommunicationPacket(CommQ) {}

  uint8_t data_type{};
  uint8_t key[32]{};

  std::vector<uint8_t> toByte() {
    /// Start basic part
    std::vector<uint8_t> result(std::begin(prefix), std::end(prefix));
    result.push_back(type);
    result.push_back(ver);
    result.insert(result.end(), std::begin(cid), std::end(cid));
    /// End basic part

    result.push_back(data_type);
    result.insert(result.end(), std::begin(key), std::end(key));
    return result;
  }
};

struct DeletionQueryPacket : public CleanCommunicationPacket{
 public:
  DeletionQueryPacket() : CleanCommunicationPacket(CommY) {}

  uint8_t dht_key[32]{};

  std::vector<uint8_t> toByte() {
    /// Start basic part
    std::vector<uint8_t> result(std::begin(prefix), std::end(prefix));
    result.push_back(type);
    result.push_back(ver);
    result.insert(result.end(), std::begin(cid), std::end(cid));
    /// End basic part

    result.insert(result.end(), std::begin(dht_key), std::end(dht_key));

    return result;
  }
};

struct StoreRequestPacket : public CleanCommunicationPacket{
 public:
  StoreRequestPacket() : CleanCommunicationPacket(CommS) {}

  uint16_t hc_length{};
  std::vector<uint8_t> hashcash;
  uint16_t length{};
  std::vector<uint8_t> data;

  std::vector<uint8_t> toByte() {
    /// Start basic part
    std::vector<uint8_t> result(std::begin(prefix), std::end(prefix));
    result.push_back(type);
    result.push_back(ver);
    result.insert(result.end(), std::begin(cid), std::end(cid));
    /// End basic part

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

  uint8_t key[32]{};
  uint8_t DA[32]{};

  std::vector<uint8_t> toByte() {
    /// Start basic part
    std::vector<uint8_t> result(std::begin(prefix), std::end(prefix));
    result.push_back(type);
    result.push_back(ver);
    result.insert(result.end(), std::begin(cid), std::end(cid));
    /// End basic part

    result.insert(result.end(), std::begin(key), std::end(key));
    result.insert(result.end(), std::begin(DA), std::end(DA));

    return result;
  }
};

struct IndexDeleteRequestPacket : public CleanCommunicationPacket{
 public:
  IndexDeleteRequestPacket() : CleanCommunicationPacket(CommX) {}

  struct item {
    uint8_t key[32]{};
    uint8_t da[32]{};
  };

  uint8_t dht_key[32]{};
  uint8_t count{};
  std::vector<item> data;

  std::vector<uint8_t> toByte() {
    /// Start basic part
    std::vector<uint8_t> result(std::begin(prefix), std::end(prefix));
    result.push_back(type);
    result.push_back(ver);
    result.insert(result.end(), std::begin(cid), std::end(cid));
    /// End basic part

    result.insert(result.end(), std::begin(dht_key), std::end(dht_key));

    result.push_back(count);

    for (auto entry : data) {
      uint8_t arr[64];
      memcpy(arr, entry.key, 64);
      result.insert(result.end(), std::begin(arr), std::end(arr));
    }

    return result;
  }
};

struct FindClosePeersRequestPacket : public CleanCommunicationPacket{
 public:
  FindClosePeersRequestPacket() : CleanCommunicationPacket(CommF) {}

  uint8_t key[32]{};

  std::vector<uint8_t> toByte() {
    /// Start basic part
    std::vector<uint8_t> result(std::begin(prefix), std::end(prefix));
    result.push_back(type);
    result.push_back(ver);
    result.insert(result.end(), std::begin(cid), std::end(cid));
    /// End basic part

    result.insert(result.end(), std::begin(key), std::end(key));

    return result;
  }
};

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
    long clean_payload_size = (long)packet->payload.size() - 38;
    if (clean_payload_size < 0) {
      LogPrint(eLogWarning, "Packet: payload too short");
      return nullptr;
    }

    CommunicationPacket res(data.type);
    res.ver = data.ver;
    memcpy(res.cid, data.cid, 32);

    res.from = std::move(packet->destination);
    std::vector<uint8_t> v_payload(packet->payload.begin() + (long)packet->payload.size() - clean_payload_size, packet->payload.end());
    res.payload = v_payload;

    return std::make_shared<CommunicationPacket>(res);

  } else {
    LogPrint(eLogWarning, "Packet: have no payload");
    return nullptr;
  }
}

} // namespace pbote

#endif // PBOTE_PACKET_H__
