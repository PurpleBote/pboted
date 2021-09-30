/**
 * Copyright (c) 2019-2020 polistern
 */

#include <mutex>
#include <thread>

#include "BoteContext.h"
#include "DHTworker.h"
#include "Packet.h"
#include "RelayPeersWorker.h"

namespace pbote {
namespace kademlia {

DHTworker DHT_worker;

DHTworker::DHTworker()
    : started_(false),
      m_worker_thread_(nullptr) {
  local_node_ = std::make_shared<Node>(context.getLocalDestination()->ToBase64());
}

DHTworker::~DHTworker() {
  stop();
}

void DHTworker::start() {
  std::string loglevel;
  pbote::config::GetOption("loglevel", loglevel);

  if (!isStarted()) {
    if (!loadNodes())
      LogPrint(eLogError, "DHT: have no  nodes for start!");

    if (loglevel == "debug") {
      LogPrint(eLogDebug, "DHT: nodes stats:");
      for ( const auto& node : m_nodes_ )
        LogPrint(eLogDebug, "DHT: ", node.second->GetIdentHash().ToBase32());
      LogPrint(eLogDebug, "DHT: nodes stats end");
    }

    started_ = true;
    m_worker_thread_ = new std::thread(std::bind(&DHTworker::run, this));
  }
}

void DHTworker::stop() {
  if (isStarted()) {
    started_ = false;
    if (m_worker_thread_) {
      m_worker_thread_->join();
      delete m_worker_thread_;
      m_worker_thread_ = nullptr;
    }
  }
}

bool DHTworker::addNode(const std::string& dest) {
  Node node;
  if (node.FromBase64(dest)) {
    size_t len = node.GetFullLen();
    uint8_t *buf = new uint8_t[len];
    return addNode(node.GetIdentHash(), buf, len);
  } else {
    LogPrint(eLogDebug, "DHT: addNode: Can't create node from base64");
    return false;
  }
}

bool DHTworker::addNode(const uint8_t *buf, size_t len) {
  Node node;
  if (node.FromBuffer(buf, len))
    return addNode(node.GetIdentHash(), buf, len);
  else {
    LogPrint(eLogDebug, "DHT: addNode: Can't create node from buffer");
    return false;
  }
}

bool DHTworker::addNode(const i2p::data::IdentHash &ident, const uint8_t *buf, size_t len) {
  if (findNode(ident)) {
    //LogPrint(eLogDebug, "DHT: addNode: Duplicated node");
    return false;
  }
  auto node = std::make_shared<Node>(buf, len);
  std::unique_lock<std::mutex> l(m_nodes_mutex_);
  return m_nodes_.insert(std::pair<i2p::data::IdentHash, std::shared_ptr<Node>>(node->GetIdentHash(), node)).second;
}

std::shared_ptr<Node> DHTworker::findNode(const i2p::data::IdentHash &ident) const {
  std::unique_lock<std::mutex> l(m_nodes_mutex_);
  auto it = m_nodes_.find(ident);
  if (it != m_nodes_.end())
    return it->second;
  else
    return nullptr;
}

//std::vector<Peer> DHTworker::getClosestNodes(i2p::data::IdentHash key) {
/*std::vector<Peer> closeNodes;
i2p::data::XORMetric minMetric;
i2p::data::IdentHash destKey = i2p::data::CreateRoutingKey(destination);
if (to_us)
  minMetric = destKey ^ local_peer_->GetIdentHash();
else
  minMetric.SetMax();
std::unique_lock<std::mutex> l(m_nodes_mutex_);
for (const auto &it: m_nodes_) {
  //if (!it.second->locked()) {
    i2p::data::XORMetric m = destKey ^it.second->GetIdentHash();
    if (m < minMetric) {
      minMetric = m;
      closeNodes.push_back(*it.second);
    }
  //}
}
return closeNodes;*/

/*
struct Sorted {
  std::shared_ptr<const Peer> node;
  i2p::data::XORMetric metric;
  bool operator<(const Sorted &other) const { return metric < other.metric; };
};

std::set<Sorted> sorted;
i2p::data::IdentHash destKey = CreateRoutingKey(key);
i2p::data::XORMetric ourMetric;
//if (to_us)
  //ourMetric = destKey ^ local_node_->GetIdentHash();
//{
  std::unique_lock<std::mutex> l(m_nodes_mutex_);
  for (const auto &it: m_nodes_) {
    if (!it.second->locked()) {
      i2p::data::XORMetric m = destKey ^it.second->GetIdentHash();
      if (ourMetric < m) continue;
      //if (sorted.size() < num)
        sorted.insert({it.second, m});
      //else if (m < sorted.rbegin()->metric) {
        //sorted.insert({it.second, m});
        //sorted.erase(std::prev(sorted.end()));
      //}
    }
  }
//}

std::vector<Peer> res;
//size_t i = 0;
for (const auto &it: sorted) {
  //if (i < num) {
    res.push_back(*it.node);
    //i++;
  //} else
    //break;
}
return res;*/

//  auto results = closestNodesLookupTask(key);
//}

//std::vector<Peer> DHTworker::getClosestNodes(i2p::data::IdentHash key, size_t num, bool to_us) {
  /*std::vector<Peer> closeNodes;
  i2p::data::XORMetric minMetric;
  i2p::data::IdentHash destKey = i2p::data::CreateRoutingKey(destination);
  if (to_us)
    minMetric = destKey ^ local_peer_->GetIdentHash();
  else
    minMetric.SetMax();
  std::unique_lock<std::mutex> l(m_nodes_mutex_);
  for (const auto &it: m_nodes_) {
    //if (!it.second->locked()) {
      i2p::data::XORMetric m = destKey ^it.second->GetIdentHash();
      if (m < minMetric) {
        minMetric = m;
        closeNodes.push_back(*it.second);
      }
    //}
  }
  return closeNodes;*/
/*
  struct Sorted {
    std::shared_ptr<const Peer> node;
    i2p::data::XORMetric metric;
    bool operator<(const Sorted &other) const { return metric < other.metric; };
  };

  std::set<Sorted> sorted;
  i2p::data::IdentHash destKey = CreateRoutingKey(key);
  i2p::data::XORMetric ourMetric;
  if (to_us)
    ourMetric = destKey ^ local_node_->GetIdentHash();
  {
    std::unique_lock<std::mutex> l(m_nodes_mutex_);
    for (const auto &it: m_nodes_) {
      if (!it.second->locked()) {
        i2p::data::XORMetric m = destKey ^ it.second->GetIdentHash();
        if (to_us && ourMetric < m) continue;
        if (sorted.size() < num)
          sorted.insert({it.second, m});
        else if (m < sorted.rbegin()->metric) {
          sorted.insert({it.second, m});
          sorted.erase(std::prev(sorted.end()));
        }
      }
    }
  }

  std::vector<Peer> res;
  size_t i = 0;
  for (const auto &it: sorted) {
    if (i < num) {
      res.push_back(*it.node);
      i++;
    } else
      break;
  }
  return res;
}
*/

std::vector<Node> DHTworker::getAllNodes() {
  std::vector<Node> result;
  for (const auto& node : m_nodes_)
    result.push_back(*node.second);
  return result;
}

std::vector<Node> DHTworker::getUnlockedNodes() {
  std::vector<Node> res;
  size_t i = 0;
  std::unique_lock<std::mutex> l(m_nodes_mutex_);
  for (const auto &it: m_nodes_) {
    if (!it.second->locked()) {
      res.push_back(*it.second);
      i++;
    }
  }
  return res;
}

std::map<std::string, pbote::CommunicationPacket> DHTworker::findOne(i2p::data::Tag<32> hash, uint8_t type) {
  return find(hash, type, false);
}

std::map<std::string, pbote::CommunicationPacket> DHTworker::findAll(i2p::data::Tag<32> hash, uint8_t type) {
  return find(hash, type, true);
}

std::map<std::string, pbote::CommunicationPacket> DHTworker::find(i2p::data::Tag<32> key, uint8_t type, bool exhaustive) {
  auto batch = std::make_shared<pbote::PacketBatch<pbote::CommunicationPacket>>();
  batch->owner = "DHTworker::find";
  LogPrint(eLogDebug, "DHT: find: Get closest nodes");

  // ToDo: just for debug, uncomment
  std::vector<Node> closestNodes = closestNodesLookupTask(key);
  //std::vector<Node> closestNodes;

  LogPrint(eLogDebug, "DHT: find: closest nodes count: ", closestNodes.size());
  if (closestNodes.size() < MIN_CLOSEST_NODES) {
    LogPrint(eLogWarning, "DHT: find: not enough nodes for find, try to use usual nodes");
    for (const auto& node : m_nodes_)
      closestNodes.push_back(*node.second);
    LogPrint(eLogDebug, "DHT: find: usual nodes count: ", closestNodes.size());
    if (closestNodes.size() < MIN_CLOSEST_NODES) {
      LogPrint(eLogWarning, "DHT: find: not enough nodes for find");
      return {};
    }
  }

  LogPrint(eLogDebug, "DHT: find: Start to find type: ", type, ", hash: ", key.ToBase64());
  for (const auto &node: closestNodes) {
    auto packet = RetrieveRequestPacket(type, key);

    //auto ptr = static_cast<uint8_t *>(static_cast<void *>(&packet));
    uint8_t arr[sizeof(pbote::RetrieveRequestPacket)];
    memcpy(arr, packet.prefix, sizeof(pbote::RetrieveRequestPacket));
    PacketForQueue q_packet(node.ToBase64(), arr, sizeof(pbote::RetrieveRequestPacket));

    std::vector<uint8_t> v_cid(std::begin(packet.cid), std::end(packet.cid));
    batch->addPacket(v_cid, q_packet);
  }
  LogPrint(eLogDebug, "DHT: find: batch.size: ", batch->packetCount());
  context.send(batch);

  if (exhaustive)
    batch->waitLast(RESPONSE_TIMEOUT);
  else
    batch->waitFist(RESPONSE_TIMEOUT);

  int counter = 0;
  while (batch->responseCount() < 1 && counter < 5) {
    LogPrint(eLogWarning, "DHT: find: have no responses, try to resend batch, try #", counter);
    context.removeBatch(batch);
    context.send(batch);

    if (exhaustive)
      batch->waitLast(RESPONSE_TIMEOUT);
    else
      batch->waitFist(RESPONSE_TIMEOUT);
    counter++;
  }
  LogPrint(eLogDebug,"DHT: find: ", batch->responseCount(), " responses for ", key.ToBase64(), ", type: ", type);
  context.removeBatch(batch);

  return batch->getResponses();
}

std::vector<std::string> DHTworker::store(i2p::data::Tag<32> hash, uint8_t type, pbote::StoreRequestPacket packet) {
  auto batch = std::make_shared<pbote::PacketBatch<pbote::CommunicationPacket>>();
  batch->owner = "DHTworker::store";
  LogPrint(eLogDebug, "DHT: store: Get closest nodes");
  // ToDo: just for debug, uncomment
  std::vector<Node> closestNodes = closestNodesLookupTask(hash);
  //std::vector<Node> closestNodes;

  // ToDo: add find locally

  LogPrint(eLogDebug, "DHT: store: closest nodes count: ", closestNodes.size());
  if (closestNodes.size() < MIN_CLOSEST_NODES) {
    LogPrint(eLogWarning, "DHT: store: not enough nodes for store, try to use usual nodes");
    for (const auto& node : m_nodes_)
      closestNodes.push_back(*node.second);
    LogPrint(eLogDebug, "DHT: store: usual nodes count: ", closestNodes.size());
    if (closestNodes.size() < MIN_CLOSEST_NODES) {
      LogPrint(eLogWarning, "DHT: store: not enough nodes for store");
      return {};
    }
  }

  LogPrint(eLogDebug, "DHT: store: Start to store type: ", type, ", hash: ", hash.ToBase64());
  for (const auto &node: closestNodes) {
    context.random_cid(packet.cid, 32);
    auto packet_bytes = packet.toByte();
    //LogPrint(eLogDebug, "DHT: store: packet_bytes size: ", packet_bytes.size());
    PacketForQueue q_packet(node.ToBase64(), packet_bytes.data(), packet_bytes.size());
    //LogPrint(eLogDebug, "DHT: store: q_packet size: ", q_packet.payload.size());

    std::vector<uint8_t> v_cid(std::begin(packet.cid), std::end(packet.cid));
    batch->addPacket(v_cid, q_packet);
  }
  LogPrint(eLogDebug, "DHT: store: batch.size: ", batch->packetCount());
  context.send(batch);

  batch->waitLast(RESPONSE_TIMEOUT);

  int counter = 0;
  while (batch->responseCount() < 1 && counter < 5) {
    LogPrint(eLogWarning, "DHT: store: have no responses, try to resend batch, try #", counter);
    context.removeBatch(batch);
    context.send(batch);
    // ToDo: remove answered nodes from batch
    batch->waitLast(RESPONSE_TIMEOUT);
    counter++;
  }
  LogPrint(eLogDebug,"DHT: find: ", batch->responseCount(), " responses for ", hash.ToBase64(), ", type: ", type);
  context.removeBatch(batch);

  std::vector<std::string> res;

  auto responses = batch->getResponses();

  res.reserve(responses.size());
  for (const auto& response : responses)
    res.push_back(response.first);

  return res;
}

std::vector<Node> DHTworker::closestNodesLookupTask(i2p::data::Tag<32> key) {
  unsigned long current_time, exec_duration;
  auto batch = std::make_shared<pbote::PacketBatch<pbote::CommunicationPacket>>();
  batch->owner = "DHTworker::closestNodesLookupTask";
  std::vector<Node> closestNodes;
  std::map<std::string, pbote::CommunicationPacket> responses;

  // set start time
  auto task_start_time = std::chrono::system_clock::now().time_since_epoch().count();
  //auto not_queried_nodes = getUnlockedNodes();
  auto req_nodes = getAllNodes();
  for (const auto& node : req_nodes) {
    // create find closest peers packet
    auto packet = findClosePeersPacket(key);

    uint8_t arr[sizeof(pbote::FindClosePeersRequestPacket)];
    memcpy(arr, packet.prefix, sizeof(pbote::FindClosePeersRequestPacket));
    PacketForQueue q_packet(node.ToBase64(), arr, sizeof(pbote::FindClosePeersRequestPacket));

    std::vector<uint8_t> v_cid(std::begin(packet.cid), std::end(packet.cid));
    // copy packet to pending task for check timeout later
    active_requests.insert(std::pair<std::vector<uint8_t>, std::shared_ptr<Node>>(v_cid, std::make_shared<Node>(node)));
    batch->addPacket(v_cid, q_packet);
  }
  //batch->waitLast(RESPONSE_TIMEOUT);

  // while unanswered requests less than Kademlia CONSTANT_ALPHA and we have non queried nodes
  //while (active_requests.size() < CONSTANT_ALPHA && !not_queried_nodes.empty()) {
  current_time = std::chrono::system_clock::now().time_since_epoch().count();
  exec_duration = (current_time - task_start_time) / 1000000000;
  while (!active_requests.empty() && exec_duration < CLOSEST_NODES_LOOKUP_TIMEOUT) {
    LogPrint(eLogDebug, "DHT: closestNodesLookupTask: batch.size: ", batch->packetCount());
    context.send(batch);
    batch->waitLast(RESPONSE_TIMEOUT);
    responses = batch->getResponses();
    if (!responses.empty()) {
      LogPrint(eLogDebug,"DHT: closestNodesLookupTask: ", responses.size(), " responses for ", key.ToBase64());
      for (auto response : responses) {
        std::vector<uint8_t> v_cid(std::begin(response.second.cid), std::end(response.second.cid));
        // check if we sent requests with this CID
        // ToDo: decrease if have no response
        if (active_requests.find(v_cid) != active_requests.end()) {
          // mark that the node sent response
          auto peer = active_requests[v_cid];
          peer->gotResponse();
          // remove node from active requests
          active_requests.erase(v_cid);
        }
      }
      // ToDo: remove in release
      if (responses.size() >= MIN_CLOSEST_NODES)
        break;
    } else {
      LogPrint(eLogWarning, "DHT: closestNodesLookupTask: have no responses, try to resend batch");
      context.removeBatch(batch);
    }
    current_time = std::chrono::system_clock::now().time_since_epoch().count();
    exec_duration = (current_time - task_start_time) / 1000000000;
  }

  // if we have at least one response
  for (auto response : responses) {
    size_t offset = 0;
    unsigned char status;
    uint16_t dataLen;

    std::memcpy(&status, response.second.payload.data(), sizeof status);
    offset += 1;
    std::memcpy(&dataLen, response.second.payload.data() + offset, sizeof dataLen);
    dataLen = ntohs(dataLen);
    offset += 2;

    if (status != StatusCode::OK)
      LogPrint(eLogWarning, "DHT: closestNodesLookupTask: status: ", statusToString(status));

    if (dataLen == 0) {
      LogPrint(eLogWarning, "DHT: closestNodesLookupTask: packet without payload, skip parsing");
      continue;
    }

    uint8_t data[dataLen];
    std::memcpy(&data, response.second.payload.data() + offset, dataLen);

    LogPrint(eLogDebug,"DHT: closestNodesLookupTask: type: ", response.second.type, ", ver: ", unsigned(response.second.ver));
    auto peers_list = packetReceived(data, dataLen);
    if (!peers_list.empty()) {
      closestNodes.insert(closestNodes.end(), peers_list.begin(), peers_list.end());
    }
  }

  // if there are no more requests to send, and no more responses to wait for, we're finished
  context.removeBatch(batch);

  current_time = std::chrono::system_clock::now().time_since_epoch().count();
  exec_duration = (current_time - task_start_time) / 1000000000;
  if (exec_duration < CLOSEST_NODES_LOOKUP_TIMEOUT) {
    //LogPrint(eLogDebug, "DHT: closestNodesLookupTask: wait for ", CLOSEST_NODES_LOOKUP_TIMEOUT - exec_duration, " sec.");
    //std::this_thread::sleep_for(std::chrono::seconds(CLOSEST_NODES_LOOKUP_TIMEOUT - exec_duration));
    LogPrint(eLogDebug, "DHT: closestNodesLookupTask: finished");
  } else {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    LogPrint(eLogDebug, "DHT: closestNodesLookupTask: finished");
  }
  return closestNodes;
}

std::vector<Node> DHTworker::packetReceived(const unsigned char *buf, size_t len) {
  size_t offset = 0;
  uint8_t type, ver;
  uint16_t nump;

  std::memcpy(&type, buf, 1);
  offset += 1;
  std::memcpy(&ver, buf + offset, 1);
  offset += 1;
  std::memcpy(&nump, buf + offset, 2);
  offset += 2;
  nump = ntohs(nump);

  if ((type == (uint8_t) 'L' || type == (uint8_t) 'P') && ver == (uint8_t) 4) {
    std::vector<Node> closestNodes;
    size_t nodes_added = 0, dup_nodes = 0;
    for (size_t i = 0; i < nump; i++) {
      if (offset == len) {
        LogPrint(eLogWarning, "DHT: packetReceived: end of packet!");
        break;
      }
      if (offset + 384 > len) {
        LogPrint(eLogWarning, "DHT: packetReceived: incomplete packet!");
        break;
      }

      uint8_t fullKey[387];
      memcpy(fullKey, buf + offset, 384);
      offset += 384;

      i2p::data::IdentityEx node;

      /// ToDo: try to create with any usual sign
      /// This is an ugly workaround, but the current version of the protocol does not allow the correct key type to be determined
      uint8_t SIGNING_KEY_TYPES[12] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
      //uint16_t CRYPTO_KEY_TYPES[5] = {0, 1, 4, 65280, 65281};

      for (uint16_t sign_type : SIGNING_KEY_TYPES) {
        fullKey[384] = sign_type;
        fullKey[385] = 0;
        fullKey[386] = 0;

        size_t res = node.FromBuffer(fullKey, 387);
        if (res > 0) {
          if (addNode(fullKey, 387)) {
            nodes_added++;
            closestNodes.emplace_back(node.ToBase64());
            //LogPrint(eLogDebug, "DHT: packetReceived: add node sign: ", sign_type, ", res: ", res);
          } else {
            dup_nodes++;
            //LogPrint(eLogWarning, "DHT: packetReceived: fail to add node with sign: ", sign_type);
          }
        } else
          LogPrint(eLogWarning, "DHT: packetReceived: fail to add node with sign: ", sign_type);
      }
    }
    LogPrint(eLogDebug, "DHT: packetReceived: nump: ", nump, ", nodes added: ", nodes_added, ", dup_nodes: ", dup_nodes);
    return closestNodes;
  } else
    return {};
}

void DHTworker::run() {
  size_t counter = 0;
  std::string loglevel;
  pbote::config::GetOption("loglevel", loglevel);

  while (started_) {
    LogPrint(eLogDebug, "DHT: main thread work, nodes: ", getNodesCount(),
             ", uptime: ", context.get_uptime(), ", bytes_recv: ", context.get_bytes_recv(),
             ", bytes_sent: ", context.get_bytes_sent());
    std::this_thread::sleep_for(std::chrono::seconds(30));
    counter++;

    /*if (counter > 20 && loglevel == "debug") {
      LogPrint(eLogDebug, "DHT: nodes stats:");
      for ( const auto& node : m_nodes_ )
        LogPrint(eLogDebug, "DHT: ", node.second->ToBase64());
      LogPrint(eLogDebug, "DHT: nodes stats end");
      counter = 0;
    }*/
  }
}

std::vector<std::string> DHTworker::readNodes() {
  std::string nodes_file_path = pbote::fs::DataDirPath("nodes.txt");
  LogPrint(eLogInfo, "DHT: readNodes: read nodes from ", nodes_file_path);
  std::ifstream nodes_file(nodes_file_path);

  if (!nodes_file.is_open()) {
    LogPrint(eLogError, "DHT: readNodes: can't open file ", nodes_file_path);
    return {};
  }

  std::vector<std::string> nodes_list;

  for (std::string line; getline(nodes_file, line);) {
    if (!line.empty() && line[0] != ('\n') && line[0] != '#')
      nodes_list.push_back(line);
  }
  return nodes_list;
}

bool DHTworker::loadNodes() {
  std::vector<std::string> nodes_list = readNodes();
  std::vector<Node> nodes;

  for (const auto& node_str : nodes_list) {
    //LogPrint(eLogDebug, "DHT: loadNodes: node_str: ", node_str);
    auto node = new Node(node_str);
    nodes.push_back(*node);
  }

  if (!nodes.empty()) {
    size_t counter = 0, dup = 0;
    for (const auto& node : nodes) {
      //LogPrint(eLogDebug, "DHT: loadNodes: node.ToBase64(): ", node.ToBase64());
      auto t_hash = node.GetIdentHash();
      bool result = m_nodes_.insert(std::pair<i2p::data::IdentHash, std::shared_ptr<Node>>(t_hash, std::make_shared<Node>(node))).second;
      if (result)
        counter++;
      else
        dup++;
    }
    if (counter == 0)
      LogPrint(eLogInfo, "DHT: loadNodes: can't load nodes, try bootstrap");
    else {
      LogPrint(eLogInfo, "DHT: loadNodes: nodes loaded: ", counter, ", duplicated: ", dup);
      return true;
    }
  }

  // Only if we have no nodes in storage
  std::vector<std::string> bootstrap_addresses;
  pbote::config::GetOption("bootstrap.address", bootstrap_addresses);

  if (!bootstrap_addresses.empty()) {
    for (auto &bootstrap_address : bootstrap_addresses) {
      i2p::data::IdentityEx new_node;
      new_node.FromBase64(bootstrap_address);

      size_t len = new_node.GetFullLen();
      uint8_t *buf = new uint8_t[len];

      new_node.ToBuffer(buf, len);
      if (addNode(buf, len))
        LogPrint(eLogDebug, "DHT: loadNodes: successfully add node: ", new_node.GetIdentHash().ToBase64());
    }
    return true;
  } else
    return false;
}

void DHTworker::writeNodes() {
  LogPrint(eLogInfo, "DHT: writeNodes: save nodes to FS");
  std::string nodes_file_path = pbote::fs::DataDirPath("nodes.txt");
  std::ofstream nodes_file(nodes_file_path);

  if (!nodes_file.is_open()) {
    LogPrint(eLogError, "DHT: writeNodes: can't open file ", nodes_file_path);
    return;
  }

  nodes_file << "# Each line is one Base64-encoded I2P destination.\n";
  nodes_file << "# Do not edit this file while pbote is running as it will be overwritten.\n\n";
  std::unique_lock<std::mutex> l(m_nodes_mutex_);
  for (const auto& node : m_nodes_)
    nodes_file << node.second->ToBase64();

  nodes_file << "\n";
  nodes_file.close();
  LogPrint(eLogInfo, "DHT: writeNodes: nodes saved to FS");
}

pbote::FindClosePeersRequestPacket DHTworker::findClosePeersPacket(i2p::data::Tag<32> key) {
  pbote::FindClosePeersRequestPacket packet;

  context.random_cid(packet.cid, 32);

  for (int i = 0; i < 32; i++)
    packet.key[i] = key.data()[i];

  return packet;
}

pbote::RetrieveRequestPacket DHTworker::RetrieveRequestPacket(uint8_t data_type, i2p::data::Tag<32> key) {
  pbote::RetrieveRequestPacket packet;

  context.random_cid(packet.cid, 32);

  for (int i = 0; i < 32; i++)
    packet.key[i] = key.data()[i];
  packet.data_type = data_type;

  return packet;
}

} // kademlia
} // pbote
