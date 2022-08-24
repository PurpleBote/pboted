/**
 * Copyright (C) 2019-2022, polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef PBOTE_DHT_WORKER_H_
#define PBOTE_DHT_WORKER_H_

#include <chrono>
#include <iostream>
#include <map>
#include <random>
#include <string>
#include <thread>
#include <utility>

#include "ConfigParser.h"
#include "DHTStorage.h"
#include "FileSystem.h"
#include "Logging.h"
#include "NetworkWorker.h"
#include "PacketHandler.h"

// libi2pd
#include "Identity.h"

namespace pbote
{
namespace kademlia
{

#define BIT_SIZE 256

/// Number of redundant storage nodes
// ToDo: change to 20 on release 0.9.0
#ifdef NDEBUG
#define KADEMLIA_CONSTANT_K 4
#else
#define KADEMLIA_CONSTANT_K 2
#endif // NDEBUG

/// The size of the sibling list for S/Kademlia
#define KADEMLIA_CONSTANT_S 100

// ToDo: Not used
// 5 is the value from the original Kademlia paper.
/// #define KADEMLIA_CONSTANT_B 5
/// #define KADEMLIA_CONSTANT_B 1

/// According to the literature, 3 is the optimum choice,
/// but until the network becomes significantly larger than S,
/// we'll use a higher value for speed.
#define KADEMLIA_CONSTANT_ALPHA 10

/// The amount of time after which a bucket is refreshed if
/// a lookup hasn't been done in its ID range
#define BUCKET_REFRESH_INTERVAL 3600

/// Time interval for Kademlia replication
/// (plus or minus <code>REPLICATE_VARIANCE</code>)
#define REPLICATE_INTERVAL 3600

/// the maximum amount of time the replication interval
/// can deviate from REPLICATE_INTERVAL
#define REPLICATE_VARIANCE (5 * 60)

/// Max. number of seconds to wait for replies to retrieve requests
#define RESPONSE_TIMEOUT 60

/// the maximum amount of time a FIND_CLOSEST_NODES can take
#define CLOSEST_NODES_LOOKUP_TIMEOUT (5 * 60)

/// 24*60*60
#define ONE_DAY_SECONDS 86400

/// the minimum nodes for find request
#ifdef NDEBUG
#define MIN_CLOSEST_NODES 10
#else
#define MIN_CLOSEST_NODES 5
#endif // NDEBUG

#define DEFAULT_NODE_FILE_NAME "nodes.txt"

struct Node : i2p::data::IdentityEx
{
  long first_seen;
  long last_seen;
  int consecutive_timeouts = 0;
  long locked_until = 0;

  Node ()
      : first_seen (0), last_seen (0), consecutive_timeouts (0),
        locked_until (0)
  {
  }

  Node (const std::string &new_destination)
      : first_seen (0), last_seen (0), consecutive_timeouts (0),
        locked_until (0)
  {
    this->FromBase64 (new_destination);
  }

  Node (const uint8_t *buf, int len)
      : first_seen (0), last_seen (0), consecutive_timeouts (0),
        locked_until (0)
  {
    this->FromBuffer (buf, len);
  }

  Node (const std::string &new_destination, long firstSeen,
        int consecutiveTimeouts, long lockedUntil)
      : first_seen (firstSeen), last_seen (0),
        consecutive_timeouts (consecutiveTimeouts), locked_until (lockedUntil)
  {
    this->FromBase64 (new_destination);
  }

  std::string
  short_name ()
  {
    std::string str = this->ToBase64 ().substr (0, 15);
    str.append ("...");
    return str;
  }

  void
  noResponse ()
  {
    consecutive_timeouts++;

    const auto current_time = std::chrono::system_clock::now ();
    const auto lock_time
        = current_time + std::chrono::minutes (consecutive_timeouts * 10);
    const auto lock_epoch = lock_time.time_since_epoch ();

    locked_until
        = std::chrono::duration_cast<std::chrono::seconds> (lock_epoch)
              .count ();
  }

  void
  gotResponse ()
  {
    last_seen = context.ts_now ();
    consecutive_timeouts = 0;
    locked_until = 0;
  }

  bool
  locked ()
  {
    return context.ts_now () < locked_until;
  }

  long
  lastseen ()
  {
    return last_seen;
  }

  void
  lastseen (long ts)
  {
    last_seen = ts;
  }

};

using sp_node = std::shared_ptr<Node>;
using HashKey = i2p::data::Tag<32>;

class DHTworker
{
public:
  DHTworker ();
  ~DHTworker ();

  void start ();
  void stop ();

  bool addNode (const std::string &dest);
  bool addNode (const uint8_t *buf, size_t len);
  bool addNode (const i2p::data::IdentityEx &identity);
  sp_node findNode (const HashKey &ident) const; /// duplication check

  sp_node getClosestNode (const HashKey &key, bool to_us);
  std::vector<sp_node> getClosestNodes (HashKey key, size_t num, bool to_us);

  std::vector<sp_node> getAllNodes ();
  std::vector<sp_node> getUnlockedNodes ();
  size_t
  getNodesCount ()
  {
    return m_nodes_.size ();
  }
  size_t
  get_unlocked_nodes_count ()
  {
    return getUnlockedNodes ().size ();
  }

  std::vector<sp_comm_pkt> findOne (HashKey hash, uint8_t type);
  std::vector<sp_comm_pkt> findAll (HashKey hash, uint8_t type);
  std::vector<sp_comm_pkt> find (HashKey hash, uint8_t type, bool exhaustive);
  std::vector<std::string> store (HashKey hash, uint8_t type,
                                  StoreRequestPacket packet);

  std::vector<std::string> deleteEmail (HashKey hash, uint8_t type,
                                        EmailDeleteRequestPacket packet);
  std::vector<std::string> deleteIndexEntry (HashKey index_dht_key,
                                             HashKey email_dht_key,
                                             HashKey del_auth);
  std::vector<std::shared_ptr<DeletionInfoPacket> >
  deletion_query (const HashKey &key);

  std::vector<sp_node> closestNodesLookupTask (HashKey key);

  void receiveRetrieveRequest (const sp_comm_pkt &packet);
  void receiveDeletionQuery (const sp_comm_pkt &packet);
  void receiveStoreRequest (const sp_comm_pkt &packet);
  void receiveEmailPacketDeleteRequest (const sp_comm_pkt &packet);
  void receiveIndexPacketDeleteRequest (const sp_comm_pkt &packet);
  void receiveFindClosePeers (const sp_comm_pkt &packet);

  /// Storage interfaces
  float
  get_storage_usage ()
  {
    return dht_storage_.limit_used ();
  }

  bool
  safe (const std::vector<uint8_t> &data)
  {
    return dht_storage_.safe (data);
  }

  std::vector<uint8_t>
  getIndex (HashKey key)
  {
    return dht_storage_.getIndex (key);
  }

  std::vector<uint8_t>
  getEmail (HashKey key)
  {
    return dht_storage_.getEmail (key);
  }

  std::vector<uint8_t>
  getContact (HashKey key)
  {
    return dht_storage_.getContact (key);
  }

private:
  void run ();

  static std::vector<std::string> readNodes ();
  bool loadNodes ();
  void writeNodes ();

  void calc_locks (std::vector<sp_comm_pkt> responses);

  static FindClosePeersRequestPacket findClosePeersPacket (HashKey key);
  static RetrieveRequestPacket retrieveRequestPacket (uint8_t data_type,
                                                      HashKey key);

  bool
  isStarted () const
  {
    return started_;
  };

  static bool
  isHealthy ()
  {
    return true;
  };

  bool started_;
  std::thread *m_worker_thread_;
  sp_node local_node_;

  mutable std::mutex m_nodes_mutex_, check_closest_mutex;
  std::map<HashKey, sp_node> m_nodes_;

  // ToDo: K-bucket/routing table and S-bucket (NEED MORE DISCUSSION)

  // pbote::fs::HashedStorage m_storage_;
  kademlia::DHTStorage dht_storage_;
};

extern DHTworker DHT_worker;

} // kademlia
} // pbote

#endif // PBOTE_DHT_WORKER_H_
