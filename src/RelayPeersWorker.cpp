/**
 * Copyright (c) 2019-2020 polistern
 */

#include <netinet/in.h>
#include <utility>

#include "Packet.h"
#include "RelayPeersWorker.h"

namespace pbote {
namespace relay {

RelayPeersWorker relay_peers_worker;

RelayPeersWorker::RelayPeersWorker()
    : started_(false),
      m_worker_thread_(nullptr),
      task_start_time(0) {}

RelayPeersWorker::~RelayPeersWorker() {
  stop();
}

void RelayPeersWorker::start() {
  started_ = true;
  if (!loadPeers())
    LogPrint(eLogError, "RelayPeers: have no peers for start");

  std::string loglevel;
  pbote::config::GetOption("loglevel", loglevel);

  if (loglevel == "debug" && !m_peers_.empty()) {
    LogPrint(eLogDebug, "RelayPeers: Relay peer stats:");
    for ( const auto& peer : m_peers_ )
      LogPrint(eLogDebug, "RelayPeers: ", peer.first.ToBase32(), " === ", peer.second->getReachability());
    LogPrint(eLogDebug, "RelayPeers: Relay peer stats end");
  }

  m_worker_thread_ = new std::thread(std::bind(&RelayPeersWorker::run, this));
}

void RelayPeersWorker::stop() {
  started_ = false;
  if (m_worker_thread_) {
    m_worker_thread_->join();
    delete m_worker_thread_;
    m_worker_thread_ = nullptr;
  }
}

void RelayPeersWorker::run() {
  size_t counter = 0;
  std::string loglevel;
  pbote::config::GetOption("loglevel", loglevel);
  while (started_) {
    task_start_time = std::chrono::system_clock::now().time_since_epoch().count();
    if (!m_peers_.empty())
      checkPeersTask();
    else
      LogPrint(eLogError, "RelayPeers: have no peers for start");

    unsigned long current_time = std::chrono::system_clock::now().time_since_epoch().count();
    unsigned long exec_duration = (current_time - task_start_time) / 1000000000;

    // ToDo: UPDATE_INTERVAL_SHORT just for tests
    LogPrint(eLogDebug, "RelayPeers: round completed, peers count: ", m_peers_.size(), ", duration: ", exec_duration);
    if (exec_duration < UPDATE_INTERVAL_SHORT) {
      LogPrint(eLogDebug, "RelayPeers: wait for ", UPDATE_INTERVAL_SHORT - exec_duration, " sec.");
      std::this_thread::sleep_for(std::chrono::seconds(UPDATE_INTERVAL_SHORT - exec_duration));
    } else {
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    counter++;
    if (counter > 50 && loglevel == "debug" && !m_peers_.empty()) {
      LogPrint(eLogDebug, "RelayPeers: Relay peer stats:");
      for ( const auto& peer : m_peers_ )
        LogPrint(eLogDebug, "RelayPeers: ", peer.first.ToBase32(), " === ", peer.second->getReachability());
      LogPrint(eLogDebug, "RelayPeers: Relay peer stats end");
      counter = 0;
    }
  }
}

void RelayPeersWorker::checkPeersTask() {
  LogPrint(eLogDebug, "RelayPeers: start new round");

  auto batch = std::make_shared<pbote::PacketBatch<pbote::CommunicationPacket>>();
  batch->owner = "RelayPeers::main";

  auto peers = getAllPeers();
  LogPrint(eLogDebug, "RelayPeers: peers.size: ", peers.size());
  for (const auto &peer : peers) {
    // If peer don't sent response we will mark further
    peer->reachable(false);
    auto packet = peerListRequestPacket();

    uint8_t arr[sizeof(pbote::PeerListRequestPacket)];
    memcpy(arr, packet.prefix, sizeof(pbote::PeerListRequestPacket));
    PacketForQueue q_packet(peer->ToBase64(), arr, sizeof(PeerListRequestPacket));

    std::vector<uint8_t> v_cid(std::begin(packet.cid), std::end(packet.cid));
    batch->addPacket(v_cid, q_packet);
  }

  LogPrint(eLogDebug, "RelayPeers: batch.size: ", batch->packetCount());
  context.send(batch);

  if (batch->waitLast(UPDATE_INTERVAL_SHORT))
    LogPrint(eLogDebug, "RelayPeers: ", batch->responseCount(), " responses received");

  auto responses = batch->getResponses();
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
      LogPrint(eLogWarning, "RelayPeers: status: ", statusToString(status));

    if (dataLen == 0) {
      LogPrint(eLogWarning, "RelayPeers: packet without payload, skip parsing");
      continue;
    }

    uint8_t data[dataLen];
    std::memcpy(&data, response.second.payload.data() + offset, dataLen);

    //LogPrint(eLogDebug, "RelayPeers: type=", response.second.type, ", ver=", unsigned(response.second.ver));
    if (response.second.ver == 5) {
      if (receivePeerListV5(data, dataLen)) {
        /// Increment peer metric back, if we have response
        // ToDo: looks like it can be too slow, need to think how it can be optimized
        for (const auto &m_peer: m_peers_) {
          if (m_peer.second->ToBase64() == response.first)
            m_peer.second->reachable(true);
          else
            m_peer.second->reachable(false);
        }
      }
      writePeers();
    } else if ( response.second.ver == 4 ) {
      if (receivePeerListV4(data, dataLen)) {
        /// Increment peer metric back, if we have response
        // ToDo: looks like it can be too slow, need to think how it can be optimized
        for (const auto &m_peer: m_peers_) {
          if (m_peer.second->ToBase64() == response.first)
            m_peer.second->reachable(true);
          else
            m_peer.second->reachable(false);
        }
      }
      // ToDo: I don't know how to save V4 peers, because we can't determine what Crypto Alg used
      writePeers();
    } else {
      LogPrint(eLogWarning, "RelayPeers: unknown packet version: ", response.second.ver);
    }
  }

  context.removeBatch(batch);
}

bool RelayPeersWorker::addPeer(const uint8_t *buf, int len) {
  i2p::data::IdentityEx identity;
  if (identity.FromBuffer(buf, len))
    return addPeer(identity);
  return false;
}

bool RelayPeersWorker::addPeer(const i2p::data::IdentityEx &identity) {
  if (findPeer(identity.GetIdentHash()))
    return false;

  std::shared_ptr<RelayPeer> peer;
  peer->FromBase64(identity.ToBase64());

  std::unique_lock<std::mutex> l(m_peers_mutex_);
  return m_peers_.insert(std::pair<i2p::data::IdentHash, std::shared_ptr<RelayPeer>>(peer->GetIdentHash(), peer)).second;
}

void RelayPeersWorker::addPeers(const std::vector<RelayPeer> &peers) {
  for (const auto &peer : peers)
    m_peers_.insert(std::pair<i2p::data::IdentHash, std::shared_ptr<RelayPeer>>(peer.GetIdentHash(),
                                                                                std::make_shared<RelayPeer>(peer.ToBase64())));
}

std::shared_ptr<RelayPeer> RelayPeersWorker::findPeer(const i2p::data::IdentHash &ident) const {
  std::unique_lock<std::mutex> l(m_peers_mutex_);
  auto it = m_peers_.find(ident);
  if (it != m_peers_.end())
    return it->second;
  else
    return nullptr;
}

std::vector<std::string> RelayPeersWorker::readPeers() {
  std::string peer_file_path = pbote::fs::DataDirPath("peers.txt");
  LogPrint(eLogInfo, "RelayPeers: read peers from ", peer_file_path);
  std::ifstream peer_file(peer_file_path);

  if (!peer_file.is_open()) {
    LogPrint(eLogError, "RelayPeers: can't open file ", peer_file_path);
    return {};
  }

  std::vector<std::string> peers_list;

  for (std::string line; getline(peer_file, line);) {
    if (!line.empty() && line[0] != ('\n') && line[0] != '#') {
      peers_list.push_back(line);
    }
  }
  return peers_list;
}

bool RelayPeersWorker::loadPeers() {
  LogPrint(eLogInfo, "RelayPeers: load peers from FS");
  std::string value_delimiter = " ";
  std::vector<RelayPeer> peers;
  std::vector<std::string> peers_list = readPeers();

  //std::unique_lock<std::mutex> l(m_peers_mutex_);
  if (!peers_list.empty()) {
    for (auto peer_str : peers_list) {
      size_t pos;
      std::string peer_s;
      while ((pos = peer_str.find(value_delimiter)) != std::string::npos) {
        peer_s = peer_str.substr(0, pos);
        peer_str.erase(0, pos + value_delimiter.length());
      }
      std::string token = peer_str.substr(0, peer_str.find(value_delimiter));
      //auto peer = new RelayPeer(peer_s);
      RelayPeer peer;
      if (peer.FromBase64(peer_s)) {
        //LogPrint(eLogDebug, "RelayPeers: stoi=", peer_str);
        peer.setSamples(std::stoi(peer_str));
        peers.push_back(peer);
      }
    }
  }
  if (!peers.empty()) {
    addPeers(peers);
    LogPrint(eLogInfo, "RelayPeers: peers loaded: ", peers.size());
    return true;
  }

  // Only if we have no peers in storage
  std::vector<std::string> bootstrap_addresses;
  pbote::config::GetOption("bootstrap.address", bootstrap_addresses);

  if (!bootstrap_addresses.empty() && peers.empty()) {
    size_t peers_added = 0;
    for (auto &bootstrap_address : bootstrap_addresses) {
      i2p::data::IdentityEx new_peer;
      new_peer.FromBase64(bootstrap_address);

      size_t len = new_peer.GetFullLen();
      uint8_t *buf = new uint8_t[len];

      new_peer.ToBuffer(buf, len);
      if (addPeer(buf, len))
        peers_added++;
      //LogPrint(eLogDebug, "RelayPeers: successfully add node: ", new_peer.ToBase64());
    }
    LogPrint(eLogDebug, "RelayPeers: added peers: ", peers_added);
    return true;
  } else
    return false;
}

void RelayPeersWorker::writePeers() {
  LogPrint(eLogInfo, "RelayPeers: save peers to FS");
  std::string peer_file_path = pbote::fs::DataDirPath("peers.txt");
  std::ofstream peer_file(peer_file_path);

  if (!peer_file.is_open()) {
    LogPrint(eLogError, "RelayPeers: can't open file ", peer_file_path);
    return;
  }
  std::unique_lock<std::mutex> l(m_peers_mutex_);

  peer_file << "# Each line is in the format: <dest> <samp>\n";
  peer_file << "#   dest  = the I2P destination\n";
  peer_file << "#   samp = samples from 0 to 100, depending on whether the peer responded\n";
  peer_file << "# The fields are separated by a space character.\n";
  peer_file << "# Lines starting with a # are ignored.\n";
  peer_file << "# Do not edit this file while pbote is running as it will be overwritten.\n\n";

  for (const auto &peer : m_peers_) {
    auto peer_data = peer.second->toString();
    size_t len = peer_data.size();
    auto buf = peer_data.c_str();
    peer_file.write((char *) buf, len);
    delete[] buf;
  }
  peer_file << "\n";
  peer_file.close();
  LogPrint(eLogInfo, "RelayPeers: peers saved to FS");
}

void RelayPeersWorker::getRandomPeers() {

}

std::vector<RelayPeer> RelayPeersWorker::getGoodPeers() {
  std::vector<RelayPeer> result;
  for (auto &m_peer : m_peers_) {
    if (m_peer.second->getReachability() > MIN_REACHABILITY)
      result.push_back(*m_peer.second);
  }
  return result;
}

std::vector<RelayPeer> RelayPeersWorker::getGoodPeers(uint8_t num) {
  auto result = getGoodPeers();
  while (result.size() > num)
    result.pop_back();
  return result;
}

std::vector<std::shared_ptr<RelayPeer>> RelayPeersWorker::getAllPeers() {
  std::vector<std::shared_ptr<RelayPeer>> result;
  for (const auto& m_peer : m_peers_)
    result.push_back(m_peer.second);
  return result;
}

bool RelayPeersWorker::receivePeerListV4(const unsigned char *buf, size_t len) {
  size_t offset = 0;
  uint8_t type, ver;
  uint16_t nump;

  std::memcpy(&type, buf, 1); offset += 1;
  std::memcpy(&ver, buf + offset, 1); offset += 1;
  std::memcpy(&nump, buf + offset, 2); offset += 2;
  nump = ntohs(nump);

  //LogPrint(eLogDebug, "RelayPeers: packetReceived: type=", type, ", ver=", unsigned(ver), ", nump=", nump);

  if ((type == (uint8_t) 'L' || type == (uint8_t) 'P') && ver == (uint8_t) 4) {
    size_t peers_added = 0, dup_peers = 0;
    for (size_t i = 0; i < nump; i++) {
      if (offset == len) {
        LogPrint(eLogWarning, "RelayPeers: receivePeerListV4: end of packet!");
        break;
      }
      if (offset + 384 > len) {
        LogPrint(eLogWarning, "RelayPeers: receivePeerListV4: incomplete packet!");
        break;
      }

      uint8_t fullKey[387];
      memcpy(fullKey, buf + offset, 384);
      offset += 384;

      i2p::data::IdentityEx peer;

      /// ToDo: try to create with any usual sign
      /// This is an ugly workaround, but the current version of the protocol does not allow the correct key type to be determined
      uint8_t SIGNING_KEY_TYPES[12] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
      //uint16_t SIGNING_KEY_TYPES[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
      //uint16_t SIGNING_KEY_TYPES[12] = {11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
      //uint16_t CRYPTO_KEY_TYPES[5] = {0, 1, 4, 65280, 65281};

      for (uint16_t sign_type : SIGNING_KEY_TYPES) {
        //uint8_t partA = static_cast<uint8_t>((sign_type & 0xFF00) >> 8);
        //uint8_t partB = static_cast<uint8_t>(sign_type & 0x00FF);
        //fullKey[385] = partA;
        //fullKey[386] = partB;
        fullKey[384] = sign_type;
        fullKey[385] = 0;
        fullKey[386] = 0;

        size_t res = peer.FromBuffer(fullKey, 387);
        if (res > 0) {
          //LogPrint(eLogDebug, "RelayPeers: packetReceived peer is ", sign_type, ", res=", res);
          //break;
          if (addPeer(fullKey, 387)) {
            //LogPrint(eLogDebug, "RelayPeers: packetReceived: add peer with sign: ", sign_type, ", res: ", res);
            peers_added++;
          } else {
            //LogPrint(eLogWarning, "RelayPeers: packetReceived: fail to add peer with sign: ", sign_type);
            dup_peers++;
          }
        } else
          LogPrint(eLogWarning, "RelayPeers: receivePeerListV4: fail to add peer with sign: ", sign_type);
      }

      /*auto *new_buf = new uint8_t[peer.GetFullLen()];
      peer.ToBuffer(new_buf, peer.GetFullLen());

      if (add_peer(new_buf, peer.GetFullLen()))
        peers_added++;
      else
        dup_peers++;*/
    }
    //LogPrint(eLogDebug, "RelayPeers: packetReceived: nump=", nump, ", peers added=", peers_added, ", dup_peers=", dup_peers);
    return true;
  } else
    return false;
}

bool RelayPeersWorker::receivePeerListV5(const unsigned char *buf, size_t len) {
  size_t offset = 0;
  uint8_t type, ver;
  uint16_t nump;

  std::memcpy(&type, buf, 1); offset += 1;
  std::memcpy(&ver, buf + offset, 1); offset += 1;
  std::memcpy(&nump, buf + offset, 2); offset += 2;
  nump = ntohs(nump);

  LogPrint(eLogDebug, "RelayPeers: receivePeerListV5: type: ", type, ", ver: ", unsigned(ver), ", peers: ", nump);

  if ((type == (uint8_t) 'L' || type == (uint8_t) 'P') && ver == (uint8_t) 5) {
    size_t peers_added = 0, dup_peers = 0;
    for (size_t i = 0; i < nump; i++) {
      if (offset == len) {
        LogPrint(eLogWarning, "RelayPeers: receivePeerListV5: end of packet!");
        break;
      }
      if (offset + 384 > len) {
        LogPrint(eLogWarning, "RelayPeers: receivePeerListV5: incomplete packet!");
        break;
      }

      i2p::data::IdentityEx peer;

      size_t key_len = peer.FromBuffer(buf + offset, len - offset);
      offset += key_len;

      //size_t res = peer.FromBuffer(fullKey, 387);
      if (key_len > 0) {
        //LogPrint(eLogDebug, "RelayPeers: packetReceived peer is ", sign_type, ", res=", res);
        //break;
        if (addPeer(peer)) {
          //LogPrint(eLogDebug, "RelayPeers: packetReceived: add peer with sign: ", sign_type, ", res: ", res);
          peers_added++;
        } else {
          //LogPrint(eLogWarning, "RelayPeers: packetReceived: fail to add peer with sign: ", sign_type);
          dup_peers++;
        }
      } else
        LogPrint(eLogWarning, "RelayPeers: receivePeerListV5: fail to add peer");
    }
    LogPrint(eLogDebug, "RelayPeers: receivePeerListV5: peers: ", nump, ", added: ", peers_added, ", dup: ", dup_peers);
    return true;
  } else
    return false;
}

void RelayPeersWorker::peerListRequestV4(const std::string &sender, const uint8_t *cid) {
  auto response = getGoodPeers();
  pbote::PeerListPacketV4 newResult;
  newResult.count = response.size();
  std::vector<uint8_t> result;
  for (const auto &peer : response) {
    auto temp_ident = peer.GetStandardIdentity();
    std::vector<uint8_t> result1(std::begin(temp_ident.publicKey), std::end(temp_ident.publicKey));
    std::vector<uint8_t> result2(std::begin(temp_ident.signingKey), std::end(temp_ident.signingKey));
    result1.insert(result1.end(), result2.begin(), result2.end());
    result.insert(result.end(), result1.begin(), result1.end());
  }
  newResult.data = result;
  pbote::ResponsePacket raw_data;

  for (int i = 0; i < 32; i++)
    raw_data.cid[i] = cid[i];

  auto ptr = reinterpret_cast<unsigned char *>(&newResult);
  raw_data.data = std::vector<uint8_t>(ptr, ptr + sizeof newResult);
  uint8_t *bytes_data = reinterpret_cast<uint8_t *>(&raw_data);

  context.send(PacketForQueue(sender, bytes_data, sizeof(ResponsePacket)));
}

void RelayPeersWorker::peerListRequestV5(const std::string &sender, const uint8_t *cid) {
  auto response = getGoodPeers();
  pbote::PeerListPacketV5 newResult;
  newResult.count = response.size();
  std::vector<uint8_t> result;
  for (const auto &peer : response) {
    auto temp_ident = peer.GetStandardIdentity();
    std::vector<uint8_t> result1(std::begin(temp_ident.publicKey), std::end(temp_ident.publicKey));
    std::vector<uint8_t> result2(std::begin(temp_ident.signingKey), std::end(temp_ident.signingKey));
    result1.insert(result1.end(), result2.begin(), result2.end());
    result.insert(result.end(), result1.begin(), result1.end());
  }
  newResult.data = result;
  pbote::ResponsePacket raw_data;

  for (int i = 0; i < 32; i++)
    raw_data.cid[i] = cid[i];

  auto ptr = reinterpret_cast<unsigned char *>(&newResult);
  raw_data.data = std::vector<uint8_t>(ptr, ptr + sizeof newResult);
  uint8_t *bytes_data = reinterpret_cast<uint8_t *>(&raw_data);

  context.send(PacketForQueue(sender, bytes_data, sizeof(ResponsePacket)));
}

pbote::PeerListRequestPacket RelayPeersWorker::peerListRequestPacket() {
  /// don't reuse request packets because PacketBatch will not add the same one more than once
  pbote::PeerListRequestPacket packet;
  context.random_cid(packet.cid, 32);
  return packet;
}

}
}