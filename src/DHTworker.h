/**
 * Copyright (c) 2019-2021 polistern
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

namespace pbote {
namespace kademlia {

#define BIT_SIZE  256
/// Number of redundant storage nodes
#define KADEMLIA_CONSTANT_K 20
/// The size of the sibling list for S/Kademlia
#define KADEMLIA_CONSTANT_S 100
/// const int KADEMLIA_CONSTANT_B = = 5;   // This is the value from the original Kademlia paper.
#define KADEMLIA_CONSTANT_B 1
/// According to the literature, 3 is the optimum choice,
/// but until the network becomes significantly larger than S, we'll use a higher value for speed.
#define KADEMLIA_CONSTANT_ALPHA 10
/// The amount of time after which a bucket is refreshed if a lookup hasn't been done in its ID range
#define BUCKET_REFRESH_INTERVAL 3600
/// Time interval for Kademlia replication (plus or minus <code>REPLICATE_VARIANCE</code>)
#define REPLICATE_INTERVAL 3600
/// the maximum amount of time the replication interval can deviate from REPLICATE_INTERVAL
#define REPLICATE_VARIANCE (5 * 60)
/// Max. number of seconds to wait for replies to retrieve requests
#define RESPONSE_TIMEOUT 60
/// the maximum amount of time a FIND_CLOSEST_NODES can take
#define CLOSEST_NODES_LOOKUP_TIMEOUT (5 * 60)
/// the minimum nodes for find request
#define MIN_CLOSEST_NODES 1

/**
 * Terms:
 * peer - any I2P router endpoint with Bote, filled with RelayPeersWorker
 * node - I2P route endpoint close to KEY, filled with CloseNodesLookupTask
 * Both started filling up with bootstrap nodes!
 */

struct Node : i2p::data::IdentityEx {
  long first_seen;
  long last_seen;
  int consecutive_timeouts = 0;
  long locked_until = 0;

  Node()
      : first_seen(0), last_seen(0), consecutive_timeouts(0), locked_until(0) {}

  Node(const std::string &new_destination)
      : first_seen(0), last_seen(0), consecutive_timeouts(0), locked_until(0) {
    this->FromBase64(new_destination);
  }

  Node(const uint8_t * buf, int len)
      : first_seen(0), last_seen(0), consecutive_timeouts(0), locked_until(0) {
    this->FromBuffer(buf, len);
  }

  Node(const std::string &new_destination, long firstSeen, int consecutiveTimeouts,
       long lockedUntil)
      : first_seen(firstSeen), last_seen(0), consecutive_timeouts(consecutiveTimeouts),
        locked_until(lockedUntil) {
    this->FromBase64(new_destination);
  }

  /*size_t fromBase64(const std::string &new_destination) {
    return this->FromBase64(new_destination);
  }*/

  void noResponse() {
    consecutive_timeouts++;
    int lockDuration = 1 << std::min(consecutive_timeouts, 10);   // in minutes
    auto time_now = std::chrono::system_clock::now().time_since_epoch().count();
    locked_until = time_now + 60*1000*lockDuration;
  }

  void gotResponse() {
    consecutive_timeouts = 0;
    locked_until = 0;
  }

  bool locked() {
    auto time_now = std::chrono::system_clock::now().time_since_epoch().count();
    return time_now < locked_until;
  }
};

class DHTworker {
 public:
  DHTworker();
  ~DHTworker();

  void start();
  void stop();

  bool addNode(const std::string& dest);
  bool addNode(const uint8_t *buf, size_t len);
  bool addNode(const i2p::data::IdentityEx &identity);
  std::shared_ptr<Node> findNode(const i2p::data::IdentHash &ident) const; /// duplication check

  std::shared_ptr<Node> getClosestNode(const i2p::data::IdentHash & key, bool to_us);
  std::vector<Node> getClosestNodes(i2p::data::IdentHash key, size_t num, bool to_us);

  std::vector<Node> getAllNodes();
  std::vector<Node> getUnlockedNodes();
  size_t getNodesCount() { return m_nodes_.size(); }

  std::vector<std::shared_ptr<pbote::CommunicationPacket>> findOne(i2p::data::Tag<32> hash, uint8_t type);
  std::vector<std::shared_ptr<pbote::CommunicationPacket>> findAll(i2p::data::Tag<32> hash, uint8_t type);
  std::vector<std::shared_ptr<pbote::CommunicationPacket>> find(i2p::data::Tag<32> hash, uint8_t type, bool exhaustive);

  std::vector<std::string> store(i2p::data::Tag<32> hash, uint8_t type, pbote::StoreRequestPacket packet);
  bool safe(const std::vector<uint8_t>& data) { return dht_storage_.safe(data); }

  std::vector<std::string> deleteEmail(i2p::data::Tag<32> hash, uint8_t type, pbote::EmailDeleteRequestPacket packet);
  std::vector<std::string> deleteIndexEntry(i2p::data::Tag<32> index_dht_key,
                                            i2p::data::Tag<32> email_dht_key,
                                            i2p::data::Tag<32> del_auth);

  std::vector<uint8_t> getIndex(i2p::data::Tag<32> key) { return dht_storage_.getIndex(key); }
  std::vector<uint8_t> getEmail(i2p::data::Tag<32> key) { return dht_storage_.getEmail(key); }
  std::vector<uint8_t> getContact(i2p::data::Tag<32> key) { return dht_storage_.getContact(key); }

  std::vector<Node> closestNodesLookupTask(i2p::data::Tag<32> key);

  std::vector<Node> receivePeerListV4(const uint8_t* buf, size_t len);
  std::vector<Node> receivePeerListV5(const uint8_t* buf, size_t len);
  void receiveRetrieveRequest(const std::shared_ptr<pbote::CommunicationPacket>& packet);
  void receiveDeletionQuery(const std::shared_ptr<pbote::CommunicationPacket>& packet);
  void receiveStoreRequest(const std::shared_ptr<pbote::CommunicationPacket>& packet);
  void receiveEmailPacketDeleteRequest(const std::shared_ptr<pbote::CommunicationPacket>& packet);
  void receiveIndexPacketDeleteRequest(const std::shared_ptr<pbote::CommunicationPacket>& packet);
  void receiveFindClosePeers(const std::shared_ptr<pbote::CommunicationPacket>& packet);

 private:
  void run();

  static std::vector<std::string> readNodes();
  bool loadNodes();
  void writeNodes();

  static pbote::FindClosePeersRequestPacket findClosePeersPacket(i2p::data::Tag<32> key);
  static pbote::RetrieveRequestPacket retrieveRequestPacket(uint8_t data_type, i2p::data::Tag<32> key);

  bool isStarted() const { return started_; };
  static bool isHealthy() { return true; };

  bool started_;
  std::thread *m_worker_thread_;
  std::shared_ptr<Node> local_node_;
  std::map<std::vector<uint8_t>, std::shared_ptr<Node>> active_requests;

  mutable std::mutex m_nodes_mutex_;
  std::map<i2p::data::IdentHash, std::shared_ptr<Node>> m_nodes_;

  // ToDo: K-bucket/routing table and S-bucket (NEED MORE DISCUSSION)

  //pbote::fs::HashedStorage m_storage_;
  pbote::kademlia::DHTStorage dht_storage_;
};

extern DHTworker DHT_worker;

}
}

#endif //PBOTE_DHT_WORKER_H_
