/**
 * Copyright (c) 2019-2021 polistern
 */

#ifndef PBOTE_SRC_RELAYPEERSWORKER_H_
#define PBOTE_SRC_RELAYPEERSWORKER_H_

#include <iostream>
#include <random>
#include <string>
#include <thread>

#include "BoteContext.h"

namespace pbote {
namespace relay {

/// maximum number of peers to keep track of
const int MAX_PEERS = 50;
/// maximum number of peers to send in a peer list (the bigger a datagram, the less chance of it getting through)
const int MAX_PEERS_TO_SEND = 20;
/// percentage of requests sent to a peer / responses received back
const int MIN_REACHABILITY = 0; //ToDo: change to 80
/// time in minutes between updating peers if no high-reachability peers are known
const int UPDATE_INTERVAL_SHORT = 60*2;
/// time in minutes between updating peers if at least one high-reachability peer is known
const int UPDATE_INTERVAL_LONG = 60*60;

class RelayPeer : public i2p::data::IdentityEx {
 public:
  RelayPeer()
      : samples(0) {}

  RelayPeer(const std::string &new_destination)
    : samples(0) {
    this->FromBase64(new_destination);
  }

  RelayPeer(const std::string &new_destination, int samples_)
      : samples(samples_) {
    this->FromBase64(new_destination);
  }

  RelayPeer(const uint8_t * buf, int len)
      : samples(0) {
    this->FromBuffer(buf, len);
  }

  ~RelayPeer() = default;

  /*size_t fromBase64(const std::string &new_destination) {
    return this->FromBase64(new_destination);
  };*/

  void reachable(bool result) {
    if (samples < 1000 && result)
      samples += 2;
    else if (samples > 0 && !result)
      samples--;
  }

  void setSamples(int s) { samples = s; }

  int getReachability() const { return samples; }

  std::string toString() { return this->ToBase64() + " " + std::to_string(samples); }

 private:
  int samples;
};

class RelayPeersWorker{
 public:
  RelayPeersWorker();
  ~RelayPeersWorker();

  void start();
  void stop();

  bool addPeer(const uint8_t *buf, int len);
  bool addPeer(const std::string& peer);
  bool addPeer(const std::shared_ptr<i2p::data::IdentityEx> &identity, int samples);
  void addPeers(const std::vector<RelayPeer>& peers);

  std::shared_ptr<RelayPeer> findPeer(const i2p::data::IdentHash &ident) const;
  std::vector<std::string> readPeers();
  void writePeers();
  bool loadPeers();

  void getRandomPeers();
  std::vector<RelayPeer> getGoodPeers();
  std::vector<RelayPeer> getGoodPeers(uint8_t num);
  std::vector<std::shared_ptr<RelayPeer>> getAllPeers();
  size_t getPeersCount() { return m_peers_.size(); };

  bool receivePeerListV4(const uint8_t* buf, size_t len);
  bool receivePeerListV5(const uint8_t* buf, size_t len);
  void peerListRequestV4(const std::string& sender, const uint8_t* cid);
  void peerListRequestV5(const std::string& sender, const uint8_t* cid);
  static pbote::PeerListRequestPacket peerListRequestPacket();

 private:
  void run();
  void checkPeersTask();

  bool started_;
  std::thread *m_worker_thread_;

  mutable std::mutex m_peers_mutex_;
  std::map<i2p::data::IdentHash, std::shared_ptr<RelayPeer>> m_peers_;

  unsigned long task_start_time;
};

extern RelayPeersWorker relay_peers_worker;

}
}
#endif //PBOTE_SRC_RELAYPEERSWORKER_H_
