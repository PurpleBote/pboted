/**
 * Copyright (C) 2019-2022 polistern
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

#include "Identity.h"

namespace pbote
{
namespace kademlia
{

#define BIT_SIZE  256

/// Number of redundant storage nodes
#define KADEMLIA_CONSTANT_K 20

/// The size of the sibling list for S/Kademlia
#define KADEMLIA_CONSTANT_S 100

// 5 is the value from the original Kademlia paper.
/// #define KADEMLIA_CONSTANT_B 5
#define KADEMLIA_CONSTANT_B 1

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

/// the minimum nodes for find request
#define MIN_CLOSEST_NODES 10

#define DEFAULT_NODE_FILE_NAME "nodes.txt"

/**
 * Terms:
 * peer - any I2P router endpoint with Bote, filled with RelayPeersWorker
 * node - I2P route endpoint close to KEY, filled with CloseNodesLookupTask
 * Both started filling up with bootstrap nodes!
 */

struct Node : i2p::data::IdentityEx
{
  long first_seen;
  long last_seen;
  int consecutive_timeouts = 0;
  long locked_until = 0;

  Node()
    : first_seen(0),
      last_seen(0),
      consecutive_timeouts(0),
      locked_until(0)
  {}

  Node(const std::string &new_destination)
    : first_seen(0),
      last_seen(0),
      consecutive_timeouts(0),
      locked_until(0)
  {
    this->FromBase64(new_destination);
  }

  Node(const uint8_t * buf, int len)
    : first_seen(0),
      last_seen(0),
      consecutive_timeouts(0),
      locked_until(0)
  {
    this->FromBuffer(buf, len);
  }

  Node(const std::string &new_destination,
       long firstSeen,
       int consecutiveTimeouts,
       long lockedUntil)
    : first_seen(firstSeen),
      last_seen(0),
      consecutive_timeouts(consecutiveTimeouts),
      locked_until(lockedUntil)
  {
    this->FromBase64(new_destination);
  }

  /*size_t fromBase64(const std::string &new_destination) {
    return this->FromBase64(new_destination);
  }*/

  std::string
  short_name ()
  {
    std::string str = this->ToBase64 ().substr(0, 15);
    str.append("...");
    return  str;
  }

  void noResponse() {
    consecutive_timeouts++;

    const auto current_time = std::chrono::system_clock::now();
    const auto lock_time =
      current_time + std::chrono::minutes(consecutive_timeouts * 10);
    const auto lock_epoch = lock_time.time_since_epoch();

    locked_until =
      std::chrono::duration_cast<std::chrono::seconds>(lock_epoch).count();
  }

  void gotResponse() {
    consecutive_timeouts = 0;
    locked_until = 0;
  }

  bool
  locked ()
  {
    const auto epoch_now = std::chrono::system_clock::now().time_since_epoch();
    auto time_now =
      std::chrono::duration_cast<std::chrono::seconds>(epoch_now).count();
    return time_now < locked_until;
  }
};

using sp_node = std::shared_ptr<Node>;
using sp_comm_packet = std::shared_ptr<pbote::CommunicationPacket>;
using HashKey = i2p::data::Tag<32>;

class DHTworker {
 public:
  DHTworker();
  ~DHTworker();

  void start();
  void stop();

  bool addNode(const std::string& dest);
  bool addNode(const uint8_t *buf, size_t len);
  bool addNode(const i2p::data::IdentityEx &identity);
  sp_node findNode(const HashKey &ident) const; /// duplication check

  sp_node getClosestNode(const HashKey & key, bool to_us);
  std::vector<sp_node> getClosestNodes(HashKey key, size_t num, bool to_us);

  std::vector<sp_node> getAllNodes();
  std::vector<sp_node> getUnlockedNodes();
  size_t getNodesCount() { return m_nodes_.size(); }
  size_t get_unlocked_nodes_count () { return getUnlockedNodes ().size (); }

  std::vector<sp_comm_packet> findOne(HashKey hash, uint8_t type);
  std::vector<sp_comm_packet> findAll(HashKey hash, uint8_t type);
  std::vector<sp_comm_packet> find(HashKey hash, uint8_t type, bool exhaustive);
  std::vector<std::string> store(HashKey hash, uint8_t type,
                                 pbote::StoreRequestPacket packet);
  

  std::vector<std::string> deleteEmail(HashKey hash, uint8_t type,
                                       pbote::EmailDeleteRequestPacket packet);
  std::vector<std::string> deleteIndexEntry(HashKey index_dht_key,
                                            HashKey email_dht_key,
                                            HashKey del_auth);

  std::vector<sp_node> closestNodesLookupTask(HashKey key);

  std::vector<sp_node> receivePeerListV4(const uint8_t* buf, size_t len);
  std::vector<sp_node> receivePeerListV5(const uint8_t* buf, size_t len);

  void receiveRetrieveRequest(const sp_comm_packet& packet);
  void receiveDeletionQuery(const sp_comm_packet& packet);
  void receiveStoreRequest(const sp_comm_packet& packet);
  void receiveEmailPacketDeleteRequest(const sp_comm_packet& packet);
  void receiveIndexPacketDeleteRequest(const sp_comm_packet& packet);
  void receiveFindClosePeers(const sp_comm_packet& packet);

  /// Storage interfaces
  float get_storage_usage() { return dht_storage_.limit_used(); }
  bool safe(const std::vector<uint8_t>& data) { return dht_storage_.safe(data); }
  std::vector<uint8_t> getIndex(HashKey key) { return dht_storage_.getIndex(key); }
  std::vector<uint8_t> getEmail(HashKey key) { return dht_storage_.getEmail(key); }
  std::vector<uint8_t> getContact(HashKey key) { return dht_storage_.getContact(key); }

 private:
  void run();

  static std::vector<std::string> readNodes();
  bool loadNodes();
  void writeNodes();

  void calc_locks (std::vector<sp_comm_packet> responses);

  static pbote::FindClosePeersRequestPacket findClosePeersPacket(HashKey key);
  static pbote::RetrieveRequestPacket retrieveRequestPacket(uint8_t data_type,
                                                            HashKey key);

  bool isStarted() const { return started_; };
  static bool isHealthy() { return true; };

  bool started_;
  std::thread *m_worker_thread_;
  sp_node local_node_;

  mutable std::mutex m_nodes_mutex_;
  std::map<HashKey, sp_node> m_nodes_;

  // ToDo: K-bucket/routing table and S-bucket (NEED MORE DISCUSSION)

  //pbote::fs::HashedStorage m_storage_;
  pbote::kademlia::DHTStorage dht_storage_;
};

extern DHTworker DHT_worker;

}
}

#endif //PBOTE_DHT_WORKER_H_
