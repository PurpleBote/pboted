/**
 * Copyright (C) 2019-2022, polistern
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
#define PEER_MIN_REACHABILITY 18 // 4/5 of ~1 day
#define PEER_MAX_REACHABILITY 24 // ~1 day

/// Time in seconds while we wait for responses
//#define RELAY_CHECK_TIMEOUT (2 * 60)
#define RELAY_CHECK_TIMEOUT 60
  
/// Time in minutes between updating peers if no high-reachability
/// peers are known
#define UPDATE_INTERVAL_SHORT 2

/// Time in minutes between updating peers if at least one high-reachability
/// peer is known
#define UPDATE_INTERVAL_LONG 60

/// 24*60*60
#define ONE_DAY_SECONDS 86400

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
    if (result)
      lastseen = context.ts_now ();

    if (result && samples_ < PEER_MAX_REACHABILITY - 1)
      samples_ += 2;
    else if (result && samples_ < PEER_MAX_REACHABILITY)
      samples_++;
    else if (!result && samples_ > 0)
      samples_--;
  }

  void
  rollback ()
  {
    samples_++;
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

  long
  last_seen ()
  {
    return lastseen;
  }

  void
  last_seen (long ts)
  {
    lastseen = ts;
  }

private:
  size_t samples_;
  long lastseen = 0;
};

using sp_peer = std::shared_ptr<RelayPeer>;
using sp_i2p_ident = std::shared_ptr<i2p::data::IdentityEx>;
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
  bool addPeer (const sp_i2p_ident &identity, int samples);
  void addPeers (const std::vector<sp_peer> &peers);
  void addPeers (const PeerListPacketV4 &peer_list);
  void addPeers (const PeerListPacketV5 &peer_list);

  sp_peer findPeer (const hash_key &ident) const;
  static std::vector<std::string> readPeers ();
  bool loadPeers ();
  void writePeers ();

  void getRandomPeers ();
  std::vector<sp_peer> getGoodPeers ();
  std::vector<sp_peer> getGoodPeers (uint8_t num);
  std::vector<sp_peer> getAllPeers ();
  size_t getPeersCount ();
  size_t get_good_peer_count ();

  void peerListRequestV4 (const sp_comm_pkt &packet);
  void peerListRequestV5 (const sp_comm_pkt &packet);
  static PeerListRequestPacket peerListRequestPacket ();

private:
  void run ();
  bool check_peers ();

  void set_start_time ();
  void set_finish_time ();
  std::chrono::seconds get_delay (bool exec_status);

  bool started_;
  std::thread *m_worker_thread_;

  mutable std::mutex m_peers_mutex_, m_check_mutex_;
  std::condition_variable m_check_round;
  std::map<hash_key, sp_peer> m_peers_;

  unsigned long exec_start_t, exec_finish_t;
};

extern RelayWorker relay_worker;

} // relay
} // pbote

#endif // PBOTED_SRC_RELAY_WORKER_H_
