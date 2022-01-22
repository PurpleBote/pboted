/**
 * Copyright (c) 2019-2022 polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef PBOTED_SRC_RELAYPEERSWORKER_H_
#define PBOTED_SRC_RELAYPEERSWORKER_H_

#include <iostream>
#include <random>
#include <string>
#include <thread>

#include "BoteContext.h"

namespace pbote
{
namespace relay
{

/// Maximum number of peers to keep track of
#define MAX_PEERS 50

/// Maximum number of peers to send in a peer list (the bigger a datagram, the
/// less chance of it getting through)
#define MAX_PEERS_TO_SEND 20

/// Percentage of requests sent to a peer / responses received back
#define PEER_MIN_REACHABILITY 80
#define PEER_MAX_REACHABILITY 1000 // for tests

/// Time in minutes between updating peers if no high-reachability peers are
/// known
#define UPDATE_INTERVAL_SHORT (2 * 60)

/// Time in minutes between updating peers if at least one high-reachability
/// peer is known
#define UPDATE_INTERVAL_LONG (60 * 60)

/// Default filename for peers file
#define PEER_FILE_NAME "peers.txt"

class RelayPeer : public i2p::data::IdentityEx
{
public:
  RelayPeer () : samples (0) {}

  RelayPeer (const std::string &new_destination) : samples (0)
  {
    this->FromBase64 (new_destination);
  }

  RelayPeer (const std::string &new_destination, size_t samples_)
      : samples (samples_)
  {
    this->FromBase64 (new_destination);
  }

  RelayPeer (const uint8_t *buf, int len) : samples (0)
  {
    this->FromBuffer (buf, len);
  }

  ~RelayPeer () = default;

  /*size_t fromBase64(const std::string &new_destination) {
    return this->FromBase64(new_destination);
  };*/

  void
  reachable (bool result)
  {
    if (result && samples < PEER_MAX_REACHABILITY - 1)
      samples += 2;
    else if (result && samples < PEER_MAX_REACHABILITY)
      samples++;
    else if (!result && samples > 0)
      samples--;
  }

  void
  setSamples (size_t s)
  {
    samples = s;
  }

  size_t
  getReachability () const
  {
    return samples;
  }

  std::string
  toString ()
  {
    return this->ToBase64 () + " " + std::to_string (samples);
  }

private:
  size_t samples;
};

class RelayPeersWorker
{
public:
  RelayPeersWorker ();
  ~RelayPeersWorker ();

  void start ();
  void stop ();

  bool addPeer (const uint8_t *buf, int len);
  bool addPeer (const std::string &peer);
  bool addPeer (const std::shared_ptr<i2p::data::IdentityEx> &identity,
                int samples);
  void addPeers (const std::vector<RelayPeer> &peers);

  std::shared_ptr<RelayPeer>
  findPeer (const i2p::data::IdentHash &ident) const;
  static std::vector<std::string> readPeers ();
  void writePeers ();
  bool loadPeers ();

  void getRandomPeers ();
  std::vector<RelayPeer> getGoodPeers ();
  std::vector<RelayPeer> getGoodPeers (uint8_t num);
  std::vector<std::shared_ptr<RelayPeer> > getAllPeers ();
  size_t
  getPeersCount ()
  {
    return m_peers_.size ();
  };

  bool receivePeerListV4 (const uint8_t *buf, size_t len);
  bool receivePeerListV5 (const uint8_t *buf, size_t len);
  void peerListRequestV4 (const std::string &sender, const uint8_t *cid);
  void peerListRequestV5 (const std::string &sender, const uint8_t *cid);
  static pbote::PeerListRequestPacket peerListRequestPacket ();

private:
  void run ();
  bool checkPeersTask ();

  bool started_;
  std::thread *m_worker_thread_;

  mutable std::mutex m_peers_mutex_;
  std::map<i2p::data::IdentHash, std::shared_ptr<RelayPeer> > m_peers_;

  unsigned long task_start_time;
};

extern RelayPeersWorker relay_peers_worker;

} // relay
} // pbote

#endif // PBOTED_SRC_RELAYPEERSWORKER_H_
