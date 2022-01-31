/**
 * Copyright (C) 2019-2022 polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef PBOTED_SRC_RELAY_WORKER_H_
#define PBOTED_SRC_RELAY_WORKER_H_

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
#define PEER_MIN_REACHABILITY 16 //
#define PEER_MAX_REACHABILITY 20 // ~1 day

/// Time in minutes while we wait for responses
#define RELAY_CHECK_TIMEOUT (2 * 60)
  
/// Time in minutes between updating peers if no high-reachability
/// peers are known
#define UPDATE_INTERVAL_SHORT 2

/// Time in minutes between updating peers if at least one high-reachability
/// peer is known
#define UPDATE_INTERVAL_LONG 60

/// Default filename for peers file
#define PEER_FILE_NAME "peers.txt"

class RelayPeer : public i2p::data::IdentityEx
{
public:
  RelayPeer ()
    : samples_ (0) {}

  RelayPeer (const std::string &new_destination)
    : samples_ (0)
  {
    this->FromBase64 (new_destination);
  }

  RelayPeer (const std::string &new_destination, size_t samples)
      : samples_ (samples)
  {
    this->FromBase64 (new_destination);
  }

  RelayPeer (const uint8_t *buf, int len)
    : samples_ (0)
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
    if (result && samples_ < PEER_MAX_REACHABILITY - 1)
      samples_ += 2;
    else if (result && samples_ < PEER_MAX_REACHABILITY)
      samples_++;
    else if (!result && samples_ > 0)
      samples_--;
  }

  bool
  reachable ()
  {
    return samples_ >= PEER_MIN_REACHABILITY;
  }

  void
  samples (size_t s)
  {
    samples_ = s;
  }

  size_t
  samples () const
  {
    return samples_;
  }

  std::string
  str ()
  {
    return this->ToBase64 () + " " + std::to_string (samples_);
  }

  std::string
  short_str ()
  {
    return this->GetIdentHash ().ToBase64 () + " " + std::to_string (samples_);
  }

private:
  size_t samples_;
};

using sp_peer = std::shared_ptr<RelayPeer>;
using hash_key = i2p::data::Tag<32>;

class RelayWorker
{
public:
  RelayWorker ();
  ~RelayWorker ();

  void start ();
  void stop ();

  bool addPeer (const uint8_t *buf, int len);
  bool addPeer (const std::string &peer);
  bool addPeer (const std::shared_ptr<i2p::data::IdentityEx> &identity,
                int samples);
  void addPeers (const std::vector<sp_peer> &peers);

  sp_peer findPeer (const hash_key &ident) const;
  static std::vector<std::string> readPeers ();
  void writePeers ();
  bool loadPeers ();

  void getRandomPeers ();
  std::vector<sp_peer> getGoodPeers ();
  std::vector<sp_peer> getGoodPeers (uint8_t num);
  std::vector<sp_peer> getAllPeers ();
  size_t getPeersCount ();
  size_t get_good_peer_count ();

  bool receivePeerListV4 (const uint8_t *buf, size_t len);
  bool receivePeerListV5 (const uint8_t *buf, size_t len);
  void peerListRequestV4 (const std::string &sender, const uint8_t *cid);
  void peerListRequestV5 (const std::string &sender, const uint8_t *cid);
  static pbote::PeerListRequestPacket peerListRequestPacket ();

private:
  void run ();
  bool check_peers ();

  void set_start_time ();
  void set_finish_time ();
  std::chrono::seconds get_delay (bool exec_status);

  bool started_;
  std::thread *m_worker_thread_;

  mutable std::mutex m_peers_mutex_;
  std::map<hash_key, sp_peer> m_peers_;

  unsigned long exec_start_t, exec_finish_t;
};

extern RelayWorker relay_worker;

} // relay
} // pbote

#endif // PBOTED_SRC_RELAY_WORKER_H_
