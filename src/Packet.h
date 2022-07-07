/**
 * Copyright (C) 2019-2022, polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef PBOTED_SRC_PACKET_H_
#define PBOTED_SRC_PACKET_H_

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

#include "Logging.h"

// libi2pd
#include "Identity.h"
#include "Tag.h"

namespace pbote
{

/// because prefix[4] + type[1] + ver[1] +  cid[32] = 38
#define COMM_DATA_LEN 38

//#define PACKET_ERROR_MALFORMED -1

const std::array<std::uint8_t, 12> PACKET_TYPE{ 0x52, 0x4b, 0x46, 0x4e,
                                                0x41, 0x51, 0x4c, 0x53,
                                                0x44, 0x58, 0x43 };
const std::array<std::uint8_t, 4> COMM_PREFIX{ 0x6D, 0x30, 0x52, 0xE9 };
const std::array<std::uint8_t, 5> BOTE_VERSION{ 0x1, 0x2, 0x3, 0x4, 0x5 };

enum StatusCode
{
  OK,
  GENERAL_ERROR,
  NO_DATA_FOUND,
  INVALID_PACKET,
  INVALID_HASHCASH,
  INSUFFICIENT_HASHCASH,
  NO_DISK_SPACE,
  DUPLICATED_DATA
};

enum version
{
  V1 = 0x01,
  V2 = 0x02,
  V3 = 0x03,
  V4 = 0x04,
  V5 = 0x05
};

enum type : uint8_t
{
  /// Data Packets
  DataE = 0x45, // encrypted email Packet
  DataU = 0x55, // unencrypted email Packet
  DataI = 0x49, // index Packet
  DataT = 0x54, // deletion info Packet
  DataL = 0x4c, // DataP = 0x50, // peer list
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

/**
 * @brief Converts status code to printable text
 *
 * @param status_code Status code
 * @return std::string Status message
 */
inline std::string
statusToString (uint8_t status_code)
{
  switch (status_code)
    {
    case StatusCode::OK:
      return { "OK" };
    case StatusCode::GENERAL_ERROR:
      return { "GENERAL ERROR" };
    case StatusCode::NO_DATA_FOUND:
      return { "NO DATA FOUND" };
    case StatusCode::INVALID_PACKET:
      return { "INVALID PACKET" };
    case StatusCode::INVALID_HASHCASH:
      return { "INVALID HASHCASH" };
    case StatusCode::INSUFFICIENT_HASHCASH:
      return { "INSUFFICIENT HASHCASH" };
    case StatusCode::NO_DISK_SPACE:
      return { "NO DISK SPACE" };
    case StatusCode::DUPLICATED_DATA:
      return { "DUPLICATED DATA" };
    default:
      return { "UNKNOWN STATUS" };
    }
}

struct PacketForQueue
{
  PacketForQueue (std::string destination, uint8_t *buf, size_t len)
      : destination (std::move (destination)), payload (buf, buf + len)
  {
  }
  std::string destination;
  std::vector<uint8_t> payload;
};

template <typename T> struct PacketBatch
{
  std::map<std::vector<uint8_t>, PacketForQueue> outgoingPackets;
  std::vector<std::shared_ptr<T> > incomingPackets;
  std::mutex m_batchMutex;
  std::condition_variable m_first, m_last;
  std::string owner;
  size_t removed = 0;

  bool
  operator== (const PacketBatch &other) const
  {
    return outgoingPackets.size () == other.outgoingPackets.size ()
           && incomingPackets.size () == other.incomingPackets.size ()
           && std::equal (outgoingPackets.begin (), outgoingPackets.end (),
                          other.outgoingPackets.begin ())
           && std::equal (incomingPackets.begin (), incomingPackets.end (),
                          other.incomingPackets.begin ());
  }

  std::map<std::vector<uint8_t>, PacketForQueue>
  getPackets ()
  {
    return outgoingPackets;
  }

  std::vector<std::shared_ptr<T> >
  getResponses ()
  {
    return incomingPackets;
  }

  bool
  contains (const std::vector<uint8_t> &id)
  {
    return outgoingPackets.find (id) != outgoingPackets.end ();
  }

  size_t
  packetCount ()
  {
    return outgoingPackets.size ();
  }

  size_t
  responseCount ()
  {
    return incomingPackets.size ();
  }

  size_t
  remain ()
  {
    size_t total_requests = packetCount () + removed;
    return total_requests - responseCount ();
  }

  void
  addPacket (const std::vector<uint8_t> &id, const PacketForQueue &packet)
  {
    outgoingPackets.insert (
        std::pair<std::vector<uint8_t>, PacketForQueue> (id, packet));
  }

  void
  removePacket (const std::vector<uint8_t> &cid)
  {
    if (outgoingPackets.erase (cid) > 0)
      removed++;
  }

  void
  removePacket (const std::string &to)
  {
    for (auto it = outgoingPackets.begin(); it != outgoingPackets.end(); it++)
      {
        if (it->second.destination == to)
          {
            outgoingPackets.erase (it->first);
            removed++;
            return;
          }
      }
  }

  void
  addResponse (std::shared_ptr<T> packet)
  {
    incomingPackets.push_back (packet);

    if (incomingPackets.size () == 1)
      m_first.notify_one ();

    if (remain () == 0)
      m_last.notify_one ();
  }

  bool
  waitFist (long timeout_sec)
  {
    std::chrono::duration<long> timeout = std::chrono::seconds (timeout_sec);
    std::unique_lock<std::mutex> lk (m_batchMutex);

    auto status = m_first.wait_for (lk, timeout);

    if (status == std::cv_status::no_timeout)
      LogPrint (eLogDebug, "Packet: Batch ", owner, " got first");

    if (status == std::cv_status::timeout)
      LogPrint (eLogDebug, "Packet: Batch ", owner, " timed out");

    lk.unlock ();
    return true;
  }

  bool
  waitLast (long timeout_sec)
  {
    std::chrono::duration<long> timeout = std::chrono::seconds (timeout_sec);
    std::unique_lock<std::mutex> lk (m_batchMutex);

    auto status = m_last.wait_for (lk, timeout);

    if (status == std::cv_status::no_timeout)
      LogPrint (eLogDebug, "Packet: Batch ", owner, " got last");

    if (status == std::cv_status::timeout)
      LogPrint (eLogDebug, "Packet: Batch ", owner, " timed out");

    lk.unlock ();
    return true;
  }
};

/// Packets

struct CommunicationPacket;

using sp_queue_pkt = std::shared_ptr<PacketForQueue>;
using sp_comm_pkt = std::shared_ptr<CommunicationPacket>;
using batch_comm_packet = PacketBatch<CommunicationPacket>;

/// Data packets
struct DataPacket
{
public:
  explicit DataPacket (uint8_t type_) : type (type_), ver (version::V4) {}
  uint8_t type;
  uint8_t ver = version::V4;
};

struct EmailEncryptedPacket : public DataPacket
{
public:
  EmailEncryptedPacket () : DataPacket (DataE) {}

  uint8_t key[32] = {0};
  int32_t stored_time = 0;
  uint8_t delete_hash[32] = {0};
  uint8_t alg = 0;
  uint16_t length = 0;
  std::vector<uint8_t> edata;

  bool
  fromBuffer (uint8_t *buf, size_t len, bool from_net)
  {
    /// 105 cause type[1] + ver[1] + key[32] + stored_time[4] + delete_hash[32]
    /// + alg[1] + length[2] + DA[32]
    if (len < 105)
      {
        LogPrint (eLogWarning, "Packet: E: fromBuffer: Payload is too short: ",
                  len);
        return {};
      }

    size_t offset = 0;

    std::memcpy (&type, buf, 1);
    offset += 1;
    std::memcpy (&ver, buf + offset, 1);
    offset += 1;

    if (type != type::DataE)
      {
        LogPrint (eLogWarning, "Packet: E: fromBuffer: Wrong type: ", type);
        return false;
      }

    if (ver != (uint8_t)4)
      {
        LogPrint (eLogWarning, "Packet: E: fromBuffer: Wrong version: ",
                  unsigned (ver));
        return false;
      }

    std::memcpy (&key, buf + offset, 32);
    offset += 32;
    std::memcpy (&stored_time, buf + offset, 4);
    offset += 4;
    std::memcpy (&delete_hash, buf + offset, 32);
    offset += 32;
    std::memcpy (&alg, buf + offset, 1);
    offset += 1;

    std::vector<uint8_t> data_for_verify (buf + offset, buf + len);

    std::memcpy (&length, buf + offset, 2);
    offset += 2;

    if (from_net)
      {
        stored_time = (int32_t)ntohl ((uint32_t)stored_time);
        length = ntohs (length);
      }

    LogPrint (eLogDebug, "Packet: E: fromBuffer: packet.stored_time: ",
              stored_time);
    LogPrint (eLogDebug, "Packet: E: fromBuffer: packet.alg: ", unsigned (alg));
    LogPrint (eLogDebug, "Packet: E: fromBuffer: packet.length: ", length);

    i2p::data::Tag<32> ver_hash (key);
    uint8_t data_hash[32];
    SHA256 (data_for_verify.data (), data_for_verify.size (), data_hash);
    i2p::data::Tag<32> cur_hash (data_hash);

    LogPrint (eLogDebug, "Packet: E: fromBuffer: ver_hash: ",
              ver_hash.ToBase64 ());
    LogPrint (eLogDebug, "Packet: E: fromBuffer: cur_hash: ",
              cur_hash.ToBase64 ());

    if (ver_hash != cur_hash)
      {
        LogPrint (eLogError, "Packet: E: fromBuffer: hash mismatch");
        return false;
      }

    LogPrint (eLogDebug, "Packet: E: fromBuffer: alg: ", unsigned (alg),
              ", length: ", length);
    std::vector<uint8_t> data (buf + offset, buf + offset + length);
    edata = data;

    return true;
  }

  std::vector<uint8_t>
  toByte ()
  {
    /// Start basic part
    std::vector<uint8_t> result;
    result.reserve (71 + edata.size ());

    result.push_back (type);
    result.push_back (ver);
    /// End basic part

    result.insert (result.end (), std::begin (key), std::end (key));

    uint8_t v_time[4] = { static_cast<uint8_t> (stored_time >> 24),
                          static_cast<uint8_t> (stored_time >> 16),
                          static_cast<uint8_t> (stored_time >> 8),
                          static_cast<uint8_t> (stored_time & 0xffff) };

    result.insert (result.end (), std::begin (v_time), std::end (v_time));
    result.insert (result.end (), std::begin (delete_hash),
                   std::end (delete_hash));

    result.push_back (alg);

    uint8_t v_length[2] = { static_cast<uint8_t> (length >> 8),
                            static_cast<uint8_t> (length & 0xff) };
    result.insert (result.end (), std::begin (v_length), std::end (v_length));
    result.insert (result.end (), edata.begin (), edata.end ());

    return result;
  }

  bool
  da_valid (const uint8_t dht_key[32], const uint8_t da[32])
  {
    /// Get hash of Delete Auth
    uint8_t delHash[32] = {0};
    SHA256 (da, 32, delHash);

    return ((memcmp (delete_hash, delHash, 32) == 0) &&
            (memcmp (key, dht_key, 32) == 0));
  }
};

struct EmailUnencryptedPacket : public DataPacket
{
public:
  EmailUnencryptedPacket ()
      : DataPacket (DataU), fr_id (0), fr_count (0), length (0)
  {
  }
  uint8_t mes_id[32] = {0};
  uint8_t DA[32] = {0};
  uint16_t fr_id = 0;
  uint16_t fr_count = 0;
  uint16_t length = 0;
  std::vector<uint8_t> data;

  std::vector<uint8_t>
  toByte ()
  {
    /// Start basic part
    std::vector<uint8_t> result;
    result.reserve (72 + data.size ());

    result.push_back (type);
    result.push_back (ver);
    /// End basic part

    result.insert (result.end (), std::begin (mes_id), std::end (mes_id));
    result.insert (result.end (), std::begin (DA), std::end (DA));

    uint8_t v_fr_id[2] = { static_cast<uint8_t> (fr_id >> 8),
                           static_cast<uint8_t> (fr_id & 0xff) };
    result.insert (result.end (), std::begin (v_fr_id), std::end (v_fr_id));

    uint8_t v_fr_count[2] = { static_cast<uint8_t> (fr_count >> 8),
                              static_cast<uint8_t> (fr_count & 0xff) };
    result.insert (result.end (), std::begin (v_fr_count),
                   std::end (v_fr_count));

    uint8_t v_length[2] = { static_cast<uint8_t> (length >> 8),
                            static_cast<uint8_t> (length & 0xff) };
    result.insert (result.end (), std::begin (v_length), std::end (v_length));
    result.insert (result.end (), data.begin (), data.end ());

    return result;
  }
};

struct IndexPacket : public DataPacket
{
public:
  IndexPacket () : DataPacket (DataI), nump (0) {}

  struct Entry
  {
    uint8_t key[32] = {0};
    uint8_t dv[32] = {0};
    int32_t time = 0;

    bool
    operator== (const Entry &rhs)
    {
      return memcmp (this->key, rhs.key, 32) != 0 &&
             memcmp (this->dv, rhs.dv, 32) != 0;
    }
  };

  uint8_t hash[32] = {0};
  uint32_t nump = 0;
  std::vector<Entry> data;

  bool
  fromBuffer (const std::vector<uint8_t> &buf, bool from_net)
  {
    if (buf.size () < COMM_DATA_LEN)
      {
        LogPrint (eLogWarning, "Packet: I: fromBuffer: Payload is too short");
        return false;
      }
    uint16_t offset = 0;

    std::memcpy (&type, buf.data (), 1);
    offset += 1;
    std::memcpy (&ver, buf.data () + offset, 1);
    offset += 1;
    std::memcpy (&hash, buf.data () + offset, 32);
    offset += 32;

    std::memcpy (&nump, buf.data () + offset, 4);
    
    //LogPrint (eLogDebug, "Packet: I: fromBuffer: nump raw: ", nump,
    //          ", ntohl: ", ntohl (nump),
    //          ", from_net: ", from_net ? "true" : "false");
    
    if (from_net)
      nump = ntohl (nump);

    offset += 4;

    LogPrint (eLogDebug, "Packet: I: fromBuffer: nump: ", nump,
              ", type: ", type, ", version: ", unsigned (ver));

    if (type != type::DataI)
      {
        LogPrint (eLogWarning, "Packet: I: fromBuffer: Wrong type: ", type);
        return false;
      }

    if (ver != (uint8_t)4)
      {
        LogPrint (eLogWarning, "Packet: I: fromBuffer: Wrong version: ",
                  unsigned (ver));
        return false;
      }

    // Check if payload length enough to parse all entries
    if (buf.size () < (COMM_DATA_LEN + (68 * nump)))
      {
        LogPrint (eLogWarning, "Packet: I: fromBuffer: Incomplete packet");
        return false;
      }

    for (uint32_t i = 0; i < nump; i++)
      {
        IndexPacket::Entry entry = {};
        std::memcpy (&entry.key, buf.data () + offset, 32);
        offset += 32;
        //i2p::data::Tag<32> key (entry.key);
        //LogPrint (eLogDebug, "Packet: I: fromBuffer: mail key: ",
        //          key.ToBase64 ());

        std::memcpy (&entry.dv, buf.data () + offset, 32);
        offset += 32;
        //i2p::data::Tag<32> dv (entry.dv);
        //LogPrint (eLogDebug, "Packet: I: fromBuffer: mail dvr: ",
        //          dv.ToBase64 ());

        uint32_t temp_time;
        std::memcpy (&temp_time, buf.data () + offset, 4);
        temp_time = ntohl (temp_time);
        std::memcpy (&entry.time, &temp_time, 4);
        //LogPrint (eLogDebug, "Packet: I: fromBuffer: time: ", entry.time);
        
        data.push_back (entry);
        offset += 4;
      }

    return true;
  }

  std::vector<uint8_t>
  toByte ()
  {
    /// Start basic part
    std::vector<uint8_t> result;
    result.reserve (COMM_DATA_LEN + (data.size () * 68));

    result.push_back (type);
    result.push_back (ver);
    /// End basic part

    result.insert (result.end (), std::begin (hash), std::end (hash));

    uint8_t v_nump[4] = { static_cast<uint8_t> (nump >> 24),
                          static_cast<uint8_t> (nump >> 16),
                          static_cast<uint8_t> (nump >> 8),
                          static_cast<uint8_t> (nump & 0xffff) };

    result.insert (result.end (), std::begin (v_nump), std::end (v_nump));

    for (auto entry : data)
      {
        uint32_t temp_time;
        std::memcpy (&temp_time, &entry.time, 4);
        temp_time = htonl (temp_time);
        std::memcpy (&entry.time, &temp_time, 4);

        uint8_t arr[68];
        memcpy (arr, entry.key, 68);
        result.insert (result.end (), std::begin (arr), std::end (arr));
      }

    return result;
  }

  int32_t
  erase_entry (const uint8_t key[32], const uint8_t DA[32])
  {
    uint8_t DV[32];
    /// Get hash of Delete Auth
    SHA256 (DA, 32, DV);

    i2p::data::Tag<32> da_h (DA), dh_h (DV);

    LogPrint (eLogDebug, "Packet: I: erase_entry: DA: ", da_h.ToBase64 ());
    LogPrint (eLogDebug, "Packet: I: erase_entry: DH: ", dh_h.ToBase64 ());

    for (uint8_t i = 0; i < (uint8_t)data.size (); i++)
      {
        i2p::data::Tag<32> dv_h (data[i].dv);
        int key_cmp = memcmp(data[i].key, key, 32);
        if (dh_h == dv_h && key_cmp == 0)
          {
            LogPrint (eLogDebug, "Packet: I: erase_entry: DV: ", dv_h.ToBase64 ());
            data.erase (data.begin () + i);
            nump = data.size ();
            //return true;
            return data[i].time;
          }
      }

    return 0;
  }
};

struct DeletionInfoPacket : public DataPacket
{
public:
  DeletionInfoPacket () : DataPacket (DataT), count (0) {}

  struct item
  {
    uint8_t key[32] = {0};
    uint8_t DA[32] = {0};
    int32_t time = 0;
  };

  uint32_t count;
  std::vector<item> data;

  bool
  fromBuffer (const std::vector<uint8_t> &buf, bool from_net)
  {
    /// Because count[4] = 4
    if (buf.size () < 4)
      {
        LogPrint (eLogWarning,
                  "Packet: T: from_comm_packet: Payload is too short: ",
                  buf.size ());
        return false;
      }
    
    uint16_t offset = 0;
    /// Start basic part
    std::memcpy (&type, buf.data () + offset, 1);
    offset += 1;
    std::memcpy (&ver, buf.data () + offset, 1);
    offset += 1;
    /// End basic part

    std::memcpy (&count, buf.data () + offset, 4);
    offset += 4;

    if (from_net)
      count = ntohl (count);

    LogPrint (eLogDebug, "Packet: T: fromBuffer: count: ", count,
              ", type: ", type, ", version: ", unsigned (ver));

    if (count == 0)
      return true;

    for (uint32_t i = 0; i < count; i++)
      {
        DeletionInfoPacket::item item;
        std::memcpy (&item.key, buf.data () + offset, 32);
        offset += 32;

        i2p::data::Tag<32> key (item.key);
        LogPrint (eLogDebug, "Packet: T: fromBuffer: key: ", key.ToBase64 ());

        std::memcpy (&item.DA, buf.data () + offset, 32);
        offset += 32;

        i2p::data::Tag<32> DA (item.DA);
        LogPrint (eLogDebug, "Packet: T: fromBuffer: DA: ", DA.ToBase64 ());

        uint32_t temp_time;
        std::memcpy (&temp_time, buf.data () + offset, 4);
        temp_time = ntohl (temp_time);
        std::memcpy (&item.time, &temp_time, 4);
        offset += 4;
        
        LogPrint (eLogDebug, "Packet: T: fromBuffer: time: ", item.time);
        
        data.push_back (item);
      }

    return true;
  }

  std::vector<uint8_t>
  toByte ()
  {
    /// Start basic part
    std::vector<uint8_t> result;
    result.reserve (6 + (data.size () * 68));

    result.push_back (type);
    result.push_back (ver);
    /// End basic part

    uint8_t v_count[4] = { static_cast<uint8_t> (count >> 24),
                           static_cast<uint8_t> (count >> 16),
                           static_cast<uint8_t> (count >> 8),
                           static_cast<uint8_t> (count & 0xffff) };

    result.insert (result.end (), std::begin (v_count), std::end (v_count));

    for (auto entry : data)
      {
        uint8_t arr[68];
        memcpy (arr, entry.key, 68);
        result.insert (result.end (), std::begin (arr), std::end (arr));
      }

    return result;
  }
};

struct PeerListPacketV4 : public DataPacket
{
public:
  PeerListPacketV4 () : DataPacket (DataL), count (0) {}

  uint16_t count;
  std::vector<i2p::data::IdentityEx> data;

  bool
  fromBuffer(uint8_t *buf, size_t len, bool from_net)
  {
    size_t offset = 0;
    std::memcpy (&type, buf, 1);
    offset += 1;
    std::memcpy (&ver, buf + offset, 1);
    offset += 1;
    std::memcpy (&count, buf + offset, 2);
    offset += 2;

    if (from_net)
      count = ntohs (count);

    if ((type != (uint8_t)'L' && type != (uint8_t)'P') || ver != (uint8_t)4)
      {
        LogPrint (eLogWarning, "Packet: L: V4: Unknown packet, type: ", type,
                  ", ver: ", unsigned (ver));
        return false;
      }

    for (size_t i = 0; i < count; i++)
      {
        if (offset == len || offset + 384 > len)
          {
            LogPrint (eLogWarning, "Packet: L: V4: Incomplete packet!");
            return false;
          }

        uint8_t fullKey[387];
        memcpy (fullKey, buf + offset, 384);
        offset += 384;

        i2p::data::IdentityEx identity;

        /// This is an workaround, but the current version of the
        /// protocol does not allow determine the correct key type
        fullKey[384] = 0;
        fullKey[385] = 0;
        fullKey[386] = 0;

        size_t res = identity.FromBuffer (fullKey, 387);
        if (res > 0)
          data.push_back (identity);
        else
          LogPrint (eLogWarning, "Packet: L: V4: Fail to create node");
      }
    LogPrint (eLogDebug, "Packet: L: V4: Nodes: ", data.size ());

    return true;
  }

  std::vector<uint8_t>
  toByte ()
  {
    /// Start basic part
    std::vector<uint8_t> result;
    result.reserve (4 + (data.size () * 384));
    result.push_back (type);
    result.push_back (ver);
    /// End basic part

    uint8_t v_count[2] = { static_cast<uint8_t> (count >> 8),
                           static_cast<uint8_t> (count & 0xff) };
    result.insert (result.end (), std::begin (v_count), std::end (v_count));

    for (auto identity : data)
    {
      size_t sz = identity.GetFullLen ();
      uint8_t t_key[sz] = {0};
      identity.ToBuffer (t_key, sz);
      uint8_t cut_key[384] = {0};
      memcpy(cut_key, t_key, 384);
      result.insert (result.end (), cut_key, cut_key + 384);
    }

    return result;
  }
};

struct PeerListPacketV5 : public DataPacket
{
public:
  PeerListPacketV5 () : DataPacket (DataL), count (0) { ver = version::V5; }

  uint16_t count;
  std::vector<i2p::data::IdentityEx> data;

  bool fromBuffer(uint8_t *buf, size_t len, bool from_net)
  {
    size_t offset = 0;
    std::memcpy (&type, buf, 1);
    offset += 1;
    std::memcpy (&ver, buf + offset, 1);
    offset += 1;
    std::memcpy (&count, buf + offset, 2);
    offset += 2;

    if (from_net)
      count = ntohs (count);

    if ((type != (uint8_t)'L' && type != (uint8_t)'P') || ver != (uint8_t)5)
      {
        LogPrint (eLogWarning,"Packet: L: V5: Unknown packet, type: ", type,
                  ", ver: ", unsigned (ver));
        return false;
      }

    for (size_t i = 0; i < count; i++)
      {
        if (offset == len || (offset + 384) > len)
          {
            LogPrint (eLogWarning, "Packet: L: V5: Incomplete packet");
            return false;
          }

        i2p::data::IdentityEx identity;

        size_t key_len = identity.FromBuffer (buf + offset, len - offset);
        offset += key_len;

        if (key_len > 0)
          data.push_back (identity);
        else
          LogPrint (eLogWarning, "Packet: L: Fail to create node");
      }
    LogPrint (eLogDebug, "Packet: L: V5: Nodes: ", data.size ());

    return true;
  }

  std::vector<uint8_t>
  toByte ()
  {
    /// Start basic part
    std::vector<uint8_t> result;
    result.reserve (4 + data.size ());

    result.push_back (type);
    result.push_back (ver);
    /// End basic part

    uint8_t v_count[2] = { static_cast<uint8_t> (count >> 8),
                           static_cast<uint8_t> (count & 0xff) };
    result.insert (result.end (), std::begin (v_count), std::end (v_count));

    for (auto identity : data)
    {
      size_t sz = identity.GetFullLen ();
      uint8_t t_key[sz] = {0};
      identity.ToBuffer (t_key, sz);
      result.insert (result.end (), t_key, t_key + sz);
    }

    return result;
  }
};

struct DirectoryEntryPacket : public DataPacket
{
public:
  DirectoryEntryPacket () : DataPacket (DataC) {}

  uint8_t key[32] = {0};
  uint16_t dest_length = 0;
  std::vector<uint8_t> dest_data;
  uint32_t salt = 0;
  uint16_t pic_length = 0;
  std::vector<uint32_t> pic;
  uint8_t compress = 0;
  uint16_t text_length = 0;
  std::vector<uint8_t> text;

  std::vector<uint8_t>
  toByte ()
  {
    /// Start basic part
    std::vector<uint8_t> result;
    result.reserve (4);

    result.push_back (type);
    result.push_back (ver);
    /// End basic part

    return {};
  }
};

/// Communication packets

struct CommunicationPacket
{
public:
  CommunicationPacket (uint8_t type_)
      : prefix{ 0x6D, 0x30, 0x52, 0xE9 }, type (type_), ver (version::V4)
  {
  }

  uint8_t prefix[4] = { 0x6D, 0x30, 0x52, 0xE9 };
  uint8_t type;
  uint8_t ver;
  uint8_t cid[32] = {0};
  std::string from;
  std::vector<uint8_t> payload;
};

struct CleanCommunicationPacket
{
public:
  CleanCommunicationPacket (uint8_t type_)
      : prefix{ 0x6D, 0x30, 0x52, 0xE9 }, type (type_), ver (version::V4)
  {
  }

  uint8_t prefix[4] = { 0x6D, 0x30, 0x52, 0xE9 };
  uint8_t type;
  uint8_t ver = version::V4;
  uint8_t cid[32] = {0};
};

/// not implemented
/*
struct RelayRequestPacket : public CleanCommunicationPacket
{
 public:
  RelayRequestPacket() : CleanCommunicationPacket(CommR) {}
};
*/

/// not implemented
/*
struct RelayReturnRequestPacket : public CleanCommunicationPacket
{
 public:
  RelayReturnRequestPacket() : CleanCommunicationPacket(CommK) {}
};
*/

/// not implemented
/*
struct FetchRequestPacket : public CleanCommunicationPacket
{
 public:
  FetchRequestPacket() : CleanCommunicationPacket(CommF) {}
};
*/

struct ResponsePacket : public CleanCommunicationPacket
{
public:
  ResponsePacket () : CleanCommunicationPacket (CommN) {}

  StatusCode status = StatusCode::OK;
  uint16_t length = 0;
  // 'I' = Index Packet
  // 'C' = Directory Entry
  // 'E' = Email Packet
  // or empty with non-OK status
  std::vector<uint8_t> data;

  bool
  fromBuffer (uint8_t *buf, size_t len, bool from_net)
  {
    /// Because COMM_DATA_LEN + status[1] + length[2] = 41
    if (len < 41)
      {
        LogPrint (eLogWarning,
                  "Packet: N: fromBuffer: Payload is too short: ", len);
        return false;
      }
    /// Skipping prefix
    uint16_t offset = 4;
    /// Start basic part
    std::memcpy (&type, buf + offset, 1);
    offset += 1;
    std::memcpy (&ver, buf + offset, 1);
    offset += 1;
    std::memcpy (&cid, buf + offset, 32);
    offset += 32;
    /// End basic part

    std::memcpy (&status, buf + offset, 1);
    offset += 1;
    std::memcpy (&length, buf + offset, 2);
    offset += 2;

    if (from_net)
      length = ntohs (length);

    LogPrint (eLogDebug, "Packet: N: fromBuffer: len: ", length,
              ", type: ", type, ", version: ", unsigned (ver));

    if (status != StatusCode::OK)
      return true;

    if (length == 0)
      return true;

    data = std::vector<uint8_t> (buf + offset, buf + offset + length);

    return true;
  }

  bool
  from_comm_packet (CommunicationPacket packet, bool from_net)
  {
    /// Because  status[1] + length[2] = 3
    if (packet.payload.size () < 3)
      {
        LogPrint (eLogWarning,
                  "Packet: N: from_comm_packet: Payload is too short: ",
                  packet.payload.size ());
        return false;
      }
    
    /// Start basic part
    std::memcpy (&type, &packet.type, 1);
    std::memcpy (&ver, &packet.ver, 1);
    std::memcpy (&cid, &packet.cid, 32);
    /// End basic part

    uint16_t offset = 0;
    std::memcpy (&status, packet.payload.data () + offset, 1);
    offset += 1;
    std::memcpy (&length, packet.payload.data () + offset, 2);
    offset += 2;

    if (from_net)
      length = ntohs (length);

    LogPrint (eLogDebug, "Packet: N: fromBuffer: len: ", length,
              ", type: ", type, ", version: ", unsigned (ver));

    /// If not OK - packet without payload, stop now
    if (status != StatusCode::OK)
      return true;

    if (length == 0)
      return true;

    if ((packet.payload.size () - offset) < length)
      {
        LogPrint (eLogWarning,
                  "Packet: N: from_comm_packet: Payload is too short: ",
                  packet.payload.size ());
        return false;
      }

    data = std::vector<uint8_t> (packet.payload.data () + offset,
                                 packet.payload.data () + offset + length);

    return true;
  }

  std::vector<uint8_t>
  toByte ()
  {
    /// Start basic part
    std::vector<uint8_t> result (std::begin (prefix), std::end (prefix));
    result.push_back (type);
    result.push_back (ver);
    result.insert (result.end (), std::begin (cid), std::end (cid));
    /// End basic part

    result.push_back (status);

    //uint8_t v_length[2] = { static_cast<uint8_t> (length >> 8),
    //                        static_cast<uint8_t> (length & 0xff) };
    uint16_t n_length = htons (length);
    uint8_t v_length[2];
    memcpy(v_length, &n_length, 2);
    result.insert (result.end (), std::begin (v_length), std::end (v_length));

    if (length > 0)
      result.insert (result.end (), data.begin (), data.end ());

    return result;
  }
};

struct PeerListRequestPacket : public CleanCommunicationPacket
{
public:
  PeerListRequestPacket () : CleanCommunicationPacket (CommA) {}

  bool
  fromBuffer (uint8_t *buf, size_t len, bool from_net)
  {
    if (len < COMM_DATA_LEN)
      {
        LogPrint (eLogWarning,
                  "Packet: A: fromBuffer: Payload is too short: ", len);
        return false;
      }
    /// Skipping prefix
    uint16_t offset = 4;
    /// Start basic part
    std::memcpy (&type, buf + offset, 1);
    offset += 1;
    std::memcpy (&ver, buf + offset, 1);
    offset += 1;
    std::memcpy (&cid, buf + offset, 32);
    offset += 32;
    /// End basic part

    return true;
  }

  std::vector<uint8_t>
  toByte ()
  {
    /// Start basic part
    std::vector<uint8_t> result (std::begin (prefix), std::end (prefix));
    result.push_back (type);
    result.push_back (ver);
    result.insert (result.end (), std::begin (cid), std::end (cid));
    /// End basic part

    return result;
  }
};

/// DHT packets

struct RetrieveRequestPacket : public CleanCommunicationPacket
{
public:
  RetrieveRequestPacket () : CleanCommunicationPacket (CommQ) {}

  uint8_t data_type = 0;
  uint8_t key[32] = {0};

  bool
  from_comm_packet (CommunicationPacket packet)
  {
    /// Because  data_type[1] + dht_key[32] = 33
    if (packet.payload.size () < 33)
      {
        LogPrint (eLogWarning,
                  "Packet: Q: from_comm_packet: Payload is too short: ",
                  packet.payload.size ());
        return false;
      }
    
    /// Start basic part
    std::memcpy (&type, &packet.type, 1);
    std::memcpy (&ver, &packet.ver, 1);
    std::memcpy (&cid, &packet.cid, 32);
    /// End basic part

    uint16_t offset = 0;
    std::memcpy (&data_type, packet.payload.data () + offset, 1);

    if (data_type != (uint8_t)'I' && data_type != (uint8_t)'E' &&
        data_type != (uint8_t)'C')
    {
      LogPrint (eLogWarning,
                "Packet: Q: from_comm_packet:Unknown packet type: ",
                data_type);
      return false;
    }

    offset += 1;
    std::memcpy (&key, packet.payload.data () + offset, 32);
    //offset += 32;

    return true;
  }

  std::vector<uint8_t>
  toByte ()
  {
    /// Start basic part
    std::vector<uint8_t> result (std::begin (prefix), std::end (prefix));
    result.push_back (type);
    result.push_back (ver);
    result.insert (result.end (), std::begin (cid), std::end (cid));
    /// End basic part

    result.push_back (data_type);
    result.insert (result.end (), std::begin (key), std::end (key));
    return result;
  }
};

struct DeletionQueryPacket : public CleanCommunicationPacket
{
public:
  DeletionQueryPacket () : CleanCommunicationPacket (CommY) {}

  uint8_t dht_key[32] = {0};

  bool
  from_comm_packet (CommunicationPacket packet)
  {
    /// Because  dht_key[32] = 32
    if (packet.payload.size () < 32)
      {
        LogPrint (eLogWarning,
                  "Packet: Y: from_comm_packet: Payload is too short: ",
                  packet.payload.size ());
        return false;
      }
    
    /// Start basic part
    std::memcpy (&type, &packet.type, 1);
    std::memcpy (&ver, &packet.ver, 1);
    std::memcpy (&cid, &packet.cid, 32);
    /// End basic part

    std::memcpy (&dht_key, packet.payload.data (), 32);

    return true;
  }

  std::vector<uint8_t>
  toByte ()
  {
    /// Start basic part
    std::vector<uint8_t> result (std::begin (prefix), std::end (prefix));
    result.push_back (type);
    result.push_back (ver);
    result.insert (result.end (), std::begin (cid), std::end (cid));
    /// End basic part

    result.insert (result.end (), std::begin (dht_key), std::end (dht_key));

    return result;
  }
};

struct StoreRequestPacket : public CleanCommunicationPacket
{
public:
  StoreRequestPacket () : CleanCommunicationPacket (CommS) {}

  uint16_t hc_length = 0;
  std::vector<uint8_t> hashcash;
  uint16_t length = 0;
  std::vector<uint8_t> data;

  bool
  from_comm_packet (CommunicationPacket packet, bool from_net)
  {
    /// Because  hc_length[2] + length[2] = 4
    if (packet.payload.size () < 4)
      {
        LogPrint (eLogWarning,
                  "Packet: S: from_comm_packet: Payload is too short: ",
                  packet.payload.size ());
        return false;
      }
    
    /// Start basic part
    std::memcpy (&type, &packet.type, 1);
    std::memcpy (&ver, &packet.ver, 1);
    std::memcpy (&cid, &packet.cid, 32);
    /// End basic part

    uint16_t offset = 0;
    std::memcpy (&hc_length, packet.payload.data () + offset, 2);
    offset += 2;

    if (from_net)
      hc_length = ntohs (hc_length);

    hashcash = std::vector<uint8_t> (packet.payload.data () + offset,
                                     packet.payload.data () + offset + hc_length);
    offset += hc_length;
    
    std::memcpy (&length, packet.payload.data () + offset, 2);
    offset += 2;

    if (from_net)
      length = ntohs (length);

    LogPrint (eLogDebug, "Packet: S: from_comm_packet: len: ", length,
              ", type: ", type, ", version: ", unsigned (ver));

    data = std::vector<uint8_t> (packet.payload.data () + offset,
                                 packet.payload.data () + offset + length);

    return true;
  }

  std::vector<uint8_t>
  toByte ()
  {
    /// Start basic part
    std::vector<uint8_t> result (std::begin (prefix), std::end (prefix));
    result.push_back (type);
    result.push_back (ver);
    result.insert (result.end (), std::begin (cid), std::end (cid));
    /// End basic part

    uint8_t v_hc_length[2] = { static_cast<uint8_t> (hc_length >> 8),
                               static_cast<uint8_t> (hc_length & 0xff) };
    result.insert (result.end (), std::begin (v_hc_length),
                   std::end (v_hc_length));
    result.insert (result.end (), hashcash.begin (), hashcash.end ());

    uint8_t v_length[2] = { static_cast<uint8_t> (length >> 8),
                            static_cast<uint8_t> (length & 0xff) };

    result.insert (result.end (), std::begin (v_length), std::end (v_length));
    result.insert (result.end (), data.begin (), data.end ());

    return result;
  }
};

struct EmailDeleteRequestPacket : public CleanCommunicationPacket
{
public:
  EmailDeleteRequestPacket () : CleanCommunicationPacket (CommD) {}

  uint8_t key[32] = {0};
  uint8_t DA[32] = {0};

  bool
  fromBuffer (uint8_t *buf, size_t len, bool from_net)
  {
    /// COMM_DATA_LEN + key[32] + DA[32] = 102
    if (len < 102)
      {
        LogPrint (eLogWarning,
                  "Packet: D: fromBuffer: Payload is too short: ", len);
        return false;
      }

    /// Skipping prefix
    uint16_t offset = 4;
    /// Start basic part
    std::memcpy (&type, buf + offset, 1);
    offset += 1;
    std::memcpy (&ver, buf + offset, 1);
    offset += 1;
    std::memcpy (&cid, buf + offset, 32);
    offset += 32;
    /// End basic part

    LogPrint (eLogDebug, "Packet: D: fromBuffer: type: ", type,
              ", version: ", unsigned (ver));

    std::memcpy (&key, buf + offset, 32);
    offset += 32;
    std::memcpy (&DA, buf + offset, 32);
    // offset += 32;
    return true;
  }

  bool
  from_comm_packet (CommunicationPacket packet)
  {
    /// Because  key[32] + DA[32] = 64
    if (packet.payload.size () < 64)
      {
        LogPrint (eLogWarning,
                  "Packet: D: from_comm_packet: Payload is too short: ",
                  packet.payload.size ());
        return false;
      }

    /// Skipping prefix
    
    /// Start basic part
    std::memcpy (&type, &packet.type, 1);
    std::memcpy (&ver, &packet.ver, 1);
    std::memcpy (&cid, &packet.cid, 32);
    /// End basic part

    LogPrint (eLogDebug, "Packet: D: from_comm_packet: type: ", type,
              ", version: ", unsigned (ver));

    uint16_t offset = 0;
    std::memcpy (&key, packet.payload.data () + offset, 32);
    offset += 32;
    std::memcpy (&DA, packet.payload.data () + offset, 32);
    // offset += 32;
    return true;
  }

  std::vector<uint8_t>
  toByte ()
  {
    /// Start basic part
    std::vector<uint8_t> result (std::begin (prefix), std::end (prefix));
    result.push_back (type);
    result.push_back (ver);
    result.insert (result.end (), std::begin (cid), std::end (cid));
    /// End basic part

    result.insert (result.end (), std::begin (key), std::end (key));
    result.insert (result.end (), std::begin (DA), std::end (DA));

    return result;
  }
};

struct IndexDeleteRequestPacket : public CleanCommunicationPacket
{
public:
  IndexDeleteRequestPacket () : CleanCommunicationPacket (CommX) {}

  struct item
  {
    uint8_t key[32] = {0};
    uint8_t da[32] = {0};
  };

  uint8_t dht_key[32] = {0};
  uint8_t count = 0;
  std::vector<item> data;

  bool
  fromBuffer (uint8_t *buf, size_t len, bool from_net)
  {
    /// COMM_DATA_LEN + count[1] + dht_key[32] + item[64] = 135 for min 1 item
    if (len < 135)
      {
        LogPrint (eLogWarning,
                  "Packet: X: fromBuffer: Payload is too short: ", len);
        return false;
      }

    /// Skipping prefix
    uint16_t offset = 4;
    /// Start basic part
    std::memcpy (&type, buf + offset, 1);
    offset += 1;
    std::memcpy (&ver, buf + offset, 1);
    offset += 1;
    std::memcpy (&cid, buf + offset, 32);
    offset += 32;
    /// End basic part

    std::memcpy (&dht_key, buf + offset, 32);
    offset += 32;
    std::memcpy (&count, buf + offset, 1);
    offset += 1;

    if (len < (size_t)(71 + (64 * count)))
      {
        LogPrint (eLogWarning, "Packet: X: fromBuffer: Payload is too short: ",
                  len);
        return false;
      }

    LogPrint (eLogDebug, "Packet: X: fromBuffer: count: ", count,
              ", type: ", type,", version: ", unsigned (ver));

    for (uint32_t i = 0; i < count; i++)
      {
        IndexDeleteRequestPacket::item item;
        std::memcpy (&item.key, buf + offset, 32);
        offset += 32;
        i2p::data::Tag<32> key (item.key);
        LogPrint (eLogDebug, "Packet: X: fromBuffer: mail key: ",
                  key.ToBase64 ());

        std::memcpy (&item.da, buf + offset, 32);
        offset += 32;
        i2p::data::Tag<32> da (item.da);
        LogPrint (eLogDebug, "Packet: X: fromBuffer: mail da: ",
                  da.ToBase64 ());

        data.push_back (item);
      }

    return true;
  }

  bool
  from_comm_packet (CommunicationPacket packet)
  {
    /// Because count[1] + dht_key[32] + item[64] = 97
    if (packet.payload.size () < 97)
      {
        LogPrint (eLogWarning,
                  "Packet: X: from_comm_packet: Payload is too short: ",
                  packet.payload.size ());
        return false;
      }
    
    /// Start basic part
    std::memcpy (&type, &packet.type, 1);
    std::memcpy (&ver, &packet.ver, 1);
    std::memcpy (&cid, &packet.cid, 32);
    /// End basic part

    uint16_t offset = 0;
    std::memcpy (&dht_key, packet.payload.data () + offset, 32);
    offset += 32;
    std::memcpy (&count, packet.payload.data () + offset, 1);
    offset += 1;

    if (packet.payload.size () < (size_t)(33 + (64 * count)))
      {
        LogPrint (eLogWarning,
                  "Packet: X: from_comm_packet: Payload is too short: ",
                  packet.payload.size ());
        return false;
      }

    LogPrint (eLogDebug, "Packet: X: from_comm_packet: count: ", count,
              ", type: ", type,", version: ", unsigned (ver));

    for (uint32_t i = 0; i < count; i++)
      {
        IndexDeleteRequestPacket::item item;
        std::memcpy (&item.key, packet.payload.data () + offset, 32);
        offset += 32;
        i2p::data::Tag<32> key (item.key);
        LogPrint (eLogDebug, "Packet: X: from_comm_packet: mail key: ",
                  key.ToBase64 ());

        std::memcpy (&item.da, packet.payload.data () + offset, 32);
        offset += 32;
        i2p::data::Tag<32> da (item.da);
        LogPrint (eLogDebug, "Packet: X: from_comm_packet: mail da: ",
                  da.ToBase64 ());

        data.push_back (item);
      }

    return true;
  }

  std::vector<uint8_t>
  toByte ()
  {
    /// Start basic part
    std::vector<uint8_t> result (std::begin (prefix), std::end (prefix));
    result.push_back (type);
    result.push_back (ver);
    result.insert (result.end (), std::begin (cid), std::end (cid));
    /// End basic part

    result.insert (result.end (), std::begin (dht_key), std::end (dht_key));

    result.push_back (count);

    for (auto entry : data)
      {
        uint8_t arr[64];
        memcpy (arr, entry.key, 64);
        result.insert (result.end (), std::begin (arr), std::end (arr));
      }

    return result;
  }
};

struct FindClosePeersRequestPacket : public CleanCommunicationPacket
{
public:
  FindClosePeersRequestPacket () : CleanCommunicationPacket (CommF) {}

  uint8_t key[32] = {0};

  std::vector<uint8_t>
  toByte ()
  {
    /// Start basic part
    std::vector<uint8_t> result (std::begin (prefix), std::end (prefix));
    result.push_back (type);
    result.push_back (ver);
    result.insert (result.end (), std::begin (cid), std::end (cid));
    /// End basic part

    result.insert (result.end (), std::begin (key), std::end (key));

    return result;
  }
};

inline std::string
ToHex (const std::string &s, bool upper_case)
{
  std::ostringstream ret;

  for (char i : s)
    ret << std::hex << std::setfill ('0') << std::setw (2)
        << (upper_case ? std::uppercase : std::nouppercase) << (int)i;

  return ret.str ();
}

inline sp_comm_pkt
parseCommPacket (const sp_queue_pkt &packet)
{
  if (packet->payload.empty ())
    {
      LogPrint (eLogWarning, "Packet: Have no payload");
      return nullptr;
    }

  if (packet->payload.size () < COMM_DATA_LEN)
    {
      LogPrint (eLogWarning, "Packet: Payload is too short");
      return nullptr;
    }

  if (memcmp(packet->payload.data (), COMM_PREFIX.data(), 4) != 0)
    {
      LogPrint (eLogWarning, "Packet: Bad prefix");
      return nullptr;
    }

  CommunicationPacket data (CommA);

  /// Skipping prefix
  size_t offset = 4;

  std::memcpy (&data.type, packet->payload.data () + offset, 1);
  offset += 1;
  std::memcpy (&data.ver, packet->payload.data () + offset, 1);
  offset += 1;
  std::memcpy (&data.cid, packet->payload.data () + offset, 32);
  offset += 32;

  auto found_type = std::find (std::begin (PACKET_TYPE),
                               std::end (PACKET_TYPE), data.type);
      
  if (found_type == std::end (PACKET_TYPE))
    {
      LogPrint (eLogWarning, "Packet: Bad type");
      return nullptr;
    }

  auto found_ver = std::find (std::begin (BOTE_VERSION),
                              std::end (BOTE_VERSION), data.ver);

  if (found_ver == std::end (BOTE_VERSION))
    {
      LogPrint (eLogWarning, "Packet: Bad version");
      return nullptr;
    }

  long clean_payload_size = (long)packet->payload.size () - offset;
  if (clean_payload_size < 0)
    {
      LogPrint (eLogWarning, "Packet: Payload is too short");
      return nullptr;
    }

  //CommunicationPacket res (data.type);
  //res.ver = data.ver;
  //memcpy (res.cid, data.cid, 32);

  data.from = std::move (packet->destination);

  data.payload = std::vector<uint8_t> (packet->payload.begin () + offset,
                                       packet->payload.end ());

  return std::make_shared<CommunicationPacket> (data);
}

} // namespace pbote

#endif // PBOTED_SRC_PACKET_H_
