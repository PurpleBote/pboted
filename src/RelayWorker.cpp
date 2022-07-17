/**
 * Copyright (C) 2019-2022, polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <netinet/in.h>
#include <utility>

#include "Packet.h"
#include "RelayWorker.h"

namespace pbote
{
namespace relay
{

RelayWorker relay_worker;

RelayWorker::RelayWorker ()
    : started_ (false),
      m_worker_thread_ (nullptr),
      exec_start_t (0),
      exec_finish_t ()
{
}

RelayWorker::~RelayWorker ()
{
  stop ();
}

void
RelayWorker::start ()
{
  started_ = true;
  if (!loadPeers ())
    LogPrint (eLogError, "Relay: No peers for start");

  m_worker_thread_ = new std::thread (std::bind (&RelayWorker::run, this));
}

void
RelayWorker::stop ()
{
  LogPrint (eLogDebug, "Relay: Stopping");
  started_ = false;
  m_check_round.notify_one ();

  if (m_worker_thread_)
    {
      m_worker_thread_->join ();
      delete m_worker_thread_;
      m_worker_thread_ = nullptr;
    }
  LogPrint (eLogDebug, "Relay: Stopped");
}

bool
RelayWorker::addPeer (const uint8_t *buf, int len)
{
  sp_i2p_ident identity = std::make_shared<i2p::data::IdentityEx> ();

  if (identity->FromBuffer (buf, len))
    return addPeer (identity, PEER_MIN_REACHABILITY);

  return false;
}

bool
RelayWorker::addPeer (const std::string &peer)
{
  sp_i2p_ident identity = std::make_shared<i2p::data::IdentityEx> ();

  if (identity->FromBase64 (peer))
    return addPeer (identity, PEER_MIN_REACHABILITY);

  return false;
}

bool
RelayWorker::addPeer (const sp_i2p_ident &identity, int samples)
{
  if (findPeer (identity->GetIdentHash ()))
    return false;

  auto local_destination = context.getLocalDestination ();
  if (local_destination->GetIdentHash () == identity->GetIdentHash ())
    {
      LogPrint (eLogDebug, "Relay: addPeer: Local destination skipped");
      return false;
    }

  sp_peer peer = std::make_shared<RelayPeer> (identity->ToBase64 (), samples);

  std::unique_lock<std::mutex> l (m_peers_mutex_);
  return m_peers_
      .insert (std::pair<hash_key, sp_peer> (peer->GetIdentHash (), peer))
      .second;
}

void
RelayWorker::addPeers (const std::vector<sp_peer> &peers)
{
  for (const auto &peer : peers)
    addPeer (peer, peer->samples ());
}

void
RelayWorker::addPeers (const PeerListPacketV4 &peer_list)
{
  size_t added = 0, dupl = 0;

  for (const auto &peer : peer_list.data)
    if (addPeer (peer.ToBase64 ()))
      added++;
    else
      dupl++;

  LogPrint (eLogDebug, "Relay: addPeers: added: ", added, ", dup: ", dupl,
            ", total: ", added + dupl);
}

void
RelayWorker::addPeers (const PeerListPacketV5 &peer_list)
{
  size_t added = 0, dupl = 0;

  for (const auto &peer : peer_list.data)
    if (addPeer (peer.ToBase64 ()))
      added++;
    else
      dupl++;

  LogPrint (eLogDebug, "Relay: addPeers: added: ", added, ", dup: ", dupl,
            ", total: ", added + dupl);
}

sp_peer
RelayWorker::findPeer (const hash_key &ident) const
{
  std::unique_lock<std::mutex> l (m_peers_mutex_);

  auto it = m_peers_.find (ident);

  if (it != m_peers_.end ())
    return it->second;

  return nullptr;
}

std::vector<std::string>
RelayWorker::readPeers ()
{
  std::string peer_file_path = pbote::fs::DataDirPath (PEER_FILE_NAME);
  LogPrint (eLogInfo, "Relay: Read peers from ", peer_file_path);
  std::ifstream peer_file (peer_file_path);

  if (!peer_file.is_open ())
    {
      LogPrint (eLogError, "Relay: Can't open file ", peer_file_path);
      return {};
    }

  std::vector<std::string> peers_list;

  for (std::string line; getline (peer_file, line);)
    {
      if (!line.empty () && line[0] != ('\n') && line[0] != '#')
        {
          peers_list.push_back (line);
        }
    }
  return peers_list;
}

bool
RelayWorker::loadPeers ()
{
  LogPrint (eLogInfo, "Relay: Load peers from FS");
  std::string value_delimiter = " ";
  std::vector<sp_peer> peers;
  std::vector<std::string> peers_list = readPeers ();

  // std::unique_lock<std::mutex> l(m_peers_mutex_);
  if (!peers_list.empty ())
    {
      for (auto peer_str : peers_list)
        {
          size_t pos;
          std::string peer_s;
          while ((pos = peer_str.find (value_delimiter)) != std::string::npos)
            {
              peer_s = peer_str.substr (0, pos);
              peer_str.erase (0, pos + value_delimiter.length ());
            }
          std::string token
              = peer_str.substr (0, peer_str.find (value_delimiter));
          RelayPeer peer;

          if (peer_s.empty ())
            continue;

          if (!peer.FromBase64 (peer_s))
            continue;

          peer.samples ((size_t)std::stoi (peer_str));
          peer.last_seen (context.ts_now ());
          LogPrint (eLogDebug, "Relay: peer: ", peer.short_str ());
          peers.push_back (std::make_shared<RelayPeer> (peer));
        }
    }

  if (!peers.empty ())
    {
      addPeers (peers);
      LogPrint (eLogInfo, "Relay: Peers loaded: ", peers.size ());
      return true;
    }

  // Only if we have no peers in storage
  std::vector<std::string> bootstrap_addresses;
  pbote::config::GetOption ("bootstrap.address", bootstrap_addresses);

  if (!bootstrap_addresses.empty () && m_peers_.empty ())
    {
      size_t peers_added = 0;
      for (const auto &bootstrap_address : bootstrap_addresses)
        {
          sp_i2p_ident new_peer = std::make_shared<i2p::data::IdentityEx> ();

          if (!bootstrap_address.empty ())
            new_peer->FromBase64 (bootstrap_address);

          if (addPeer (new_peer, PEER_MIN_REACHABILITY))
            peers_added++;
          LogPrint (eLogDebug, "Relay: Successfully add node: ",
                    new_peer->ToBase64 ());
        }
      LogPrint (eLogInfo, "Relay: Added peers: ", peers_added);
      return true;
    }
  else
    return false;
}

void
RelayWorker::writePeers ()
{
  LogPrint (eLogInfo, "Relay: Save peers to FS");
  std::string peer_file_path = pbote::fs::DataDirPath (PEER_FILE_NAME);
  std::ofstream peer_file (peer_file_path);

  if (!peer_file.is_open ())
    {
      LogPrint (eLogError, "Relay: Can't open file ", peer_file_path);
      return;
    }
  std::unique_lock<std::mutex> l (m_peers_mutex_);

  peer_file << "# Each line is in the format: <dest> <samp>\n";
  peer_file << "#   dest = the I2P destination\n";
  peer_file << "#   samp = samples from 0 to 24, depending on whether the "
               "peer responded\n";
  peer_file << "# The fields are separated by a space character.\n";
  peer_file << "# Lines starting with a # are ignored.\n";
  peer_file << "# Do not edit this file while pbote is running as it will be "
               "overwritten.\n\n";

  size_t saved = 0;
  for (const auto &peer : m_peers_)
    {
      peer_file << peer.second->str ();
      peer_file << "\n";
      saved++;
    }

  peer_file.close ();
  LogPrint (eLogDebug, "Relay: ", saved, " peer(s) saved to FS");
}

void
//sp_peer
RelayWorker::getRandomPeers ()
{
}

std::vector<sp_peer>
RelayWorker::getGoodPeers ()
{
  std::vector<sp_peer> result;

  for (const auto &m_peer : m_peers_)
    {
      if (m_peer.second->reachable ())
        result.push_back (m_peer.second);
    }

  return result;
}

std::vector<sp_peer>
RelayWorker::getGoodPeers (uint8_t num)
{
  auto result = getGoodPeers ();

  while (result.size () > num)
    result.pop_back ();

  return result;
}

std::vector<sp_peer>
RelayWorker::getAllPeers ()
{
  std::vector<sp_peer> result;

  for (const auto &m_peer : m_peers_)
    result.push_back (m_peer.second);

  return result;
}

size_t
RelayWorker::getPeersCount ()
{
  return m_peers_.size ();
}

size_t
RelayWorker::get_good_peer_count ()
{
  return getGoodPeers ().size ();
}

void
RelayWorker::peerListRequestV4 (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Relay: peerListRequestV4: request from: ",
            packet->from.substr (0, 15), "...");
  if (addPeer (packet->from))
    {
      LogPrint (eLogDebug,
                "Relay: peerListRequestV4: Requester added to peers list");
    }

  auto good_peers = getGoodPeers (MAX_PEERS_TO_SEND);
  PeerListPacketV4 peer_list;
  peer_list.count = good_peers.size ();

  for (const auto &peer : good_peers)
    {
      i2p::data::IdentityEx identity;
      identity.FromBase64 (peer->ToBase64 ());
      peer_list.data.push_back (identity);
    }

  ResponsePacket response;
  memcpy (response.cid, packet->cid, 32);
  response.status = StatusCode::OK;
  response.data = peer_list.toByte ();
  response.length = response.data.size ();
  auto data = response.toByte ();

  context.send (PacketForQueue (packet->from, data.data (), data.size ()));
  LogPrint (eLogInfo, "Relay: peerListRequestV4: Send response with ",
            peer_list.count, " peer(s)");
}

void
RelayWorker::peerListRequestV5 (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "Relay: peerListRequestV5: Request from: ",
            packet->from.substr (0, 15), "...");

  if (addPeer (packet->from))
    {
      LogPrint (eLogDebug,
                "Relay: peerListRequestV5: Requester added to peers list");
    }

  auto good_peers = getGoodPeers (MAX_PEERS_TO_SEND);
  PeerListPacketV5 peer_list;
  peer_list.count = good_peers.size ();

  for (const auto &peer : good_peers)
    {
      i2p::data::IdentityEx identity;
      identity.FromBase64 (peer->ToBase64 ());
      peer_list.data.push_back (identity);
    }

  ResponsePacket response;
  memcpy (response.cid, packet->cid, 32);
  response.status = StatusCode::OK;
  response.data = peer_list.toByte ();
  response.length = response.data.size ();
  auto data = response.toByte ();

  context.send (PacketForQueue (packet->from, data.data (), data.size ()));
  LogPrint (eLogInfo, "Relay: peerListRequestV5: Send response with ",
            peer_list.count, " peer(s)");
}

PeerListRequestPacket
RelayWorker::peerListRequestPacket ()
{
  /// don't reuse request packets because PacketBatch will not
  /// add the same one more than once
  PeerListRequestPacket packet;

  /// Java will be answer with v4, pboted - with v5,
  /// so we can determine who is who
  packet.ver = 5;
  context.random_cid (packet.cid, 32);
  return packet;
}

void
RelayWorker::run ()
{
  /// To prevent too quick start
  std::this_thread::sleep_for (std::chrono::seconds(15));
  bool task_status = false;

  while (started_)
    {
      set_start_time ();

      if (!m_peers_.empty ())
        task_status = check_peers ();
      else
        LogPrint (eLogError, "Relay: No peers for start");

      set_finish_time ();

      auto delay = get_delay (task_status);
      LogPrint (eLogDebug, "Relay: Wait for ", (delay.count () / 60), " min.");

      std::unique_lock<std::mutex> lk (m_check_mutex_);
      auto status = m_check_round.wait_for (lk, std::chrono::seconds(delay));

      if (status == std::cv_status::no_timeout)
        LogPrint (eLogDebug, "Relay: Got notification");

      if (status == std::cv_status::timeout)
        LogPrint (eLogDebug, "Relay: Waiting finished");

      lk.unlock ();
    }
}

bool
RelayWorker::check_peers ()
{
  LogPrint (eLogDebug, "Relay: Start new round");
  size_t reachable_peers = 0;

  auto batch = std::make_shared<batch_comm_packet> ();
  batch->owner = "relay::main";

  auto peers = getAllPeers ();
  LogPrint (eLogDebug, "Relay: Peers count: ", peers.size ());
  for (const auto &peer : peers)
    {
      // If peer responde we will mark further
      peer->reachable (false);

      auto packet = peerListRequestPacket ();
      auto bytes = packet.toByte ();
      PacketForQueue q_packet (peer->ToBase64 (), bytes.data (), bytes.size ());
      std::vector<uint8_t> vcid (std::begin (packet.cid), std::end (packet.cid));
      batch->addPacket (vcid, q_packet);
    }

  LogPrint (eLogDebug, "Relay: Batch size: ", batch->packetCount ());
  context.send (batch);
  batch->waitLast (RELAY_CHECK_TIMEOUT);
  context.removeBatch (batch);

  auto responses = batch->getResponses ();

  if (responses.empty ())
    {
      LogPrint (eLogWarning, "Relay: No responses");
      /// Rollback samples, if have no responses at all
      /// Usually in network error case
      for (const auto &peer : m_peers_)
        peer.second->rollback ();

      return false;
    }

  for (const auto &response : responses)
    {
      if (response->type != type::CommN)
        {
          // ToDo: looks like in case if we got request to ourself
          // for now  we just skip it
          LogPrint (eLogWarning,
                    "Relay: Got non-response packet in batch, type: ",
                    response->type, ", ver: ", unsigned (response->ver));
          continue;
        }

      ResponsePacket res_packet;
      bool parsed = res_packet.from_comm_packet (*response, true);

      if (!parsed)
        {
          LogPrint (eLogWarning, "Relay: Can't parse response packet ");
          continue;
        }

      /// Increment peer metric back, if we have valid Response Packet
      for (const auto &m_peer : m_peers_)
        {
          if (m_peer.second->ToBase64 () == response->from)
            {
              LogPrint (eLogDebug, "Relay: Got response, mark reachable");
              m_peer.second->reachable (true);
              reachable_peers++;
            }
        }

      if (res_packet.status != StatusCode::OK)
        {
          LogPrint (eLogWarning, "Relay: Response status: ",
                    statusToString (res_packet.status));
          continue;
        }

      if (unsigned (res_packet.data[1]) == 5)
        {
          PeerListPacketV5 peer_list;
          parsed = peer_list.fromBuffer (res_packet.data.data (),
                                         res_packet.data.size (), true);
          if (!parsed)
            {
              LogPrint (eLogWarning, "Relay: Can't parse V5 packet");
              continue;
            }

          addPeers(peer_list);
        }
      else if (unsigned (res_packet.data[1]) == 4)
        {
          PeerListPacketV4 peer_list;
          parsed = peer_list.fromBuffer (res_packet.data.data (),
                                         res_packet.data.size (), true);
          if (!parsed)
            {
              LogPrint (eLogWarning, "Relay: Can't parse V4 packet");
              continue;
            }

          addPeers(peer_list);
        }
      else
        {
          LogPrint (eLogWarning, "Relay: Unknown version: ", response->ver);
          continue;
        }
    }

  LogPrint (eLogDebug, "Relay: Reachable peers: ", reachable_peers);

  context.removeBatch (batch);

  size_t removed = 0;
  for (auto peer : m_peers_)
    {
      long peer_ls = peer.second->last_seen ();
      long sec_now = context.ts_now ();
      if (((sec_now - peer_ls) > ONE_DAY_SECONDS) &&
          peer.second->samples () == 0)
        {
          //m_peers_.erase (peer.first);
          removed++;
          LogPrint (eLogDebug, "Relay: Remove unseen peer: ",
                    peer.second->short_str ());
        }
    }

  LogPrint (eLogDebug, "Relay: Unseen peers removed: ", removed);

  writePeers ();

  return true;
}

void
RelayWorker::set_start_time ()
{
  exec_start_t = context.ts_now ();
}

void
RelayWorker::set_finish_time ()
{
  exec_finish_t = context.ts_now ();
}

std::chrono::seconds
RelayWorker::get_delay (bool exec_status)
{
  unsigned long interval;

  if (exec_status)
    interval = UPDATE_INTERVAL_LONG;
  else
    interval = UPDATE_INTERVAL_SHORT;

  /// Convert minutes to seconds
  interval = interval * 60;

  if (exec_finish_t <= exec_start_t)
    return std::chrono::seconds(1);

  unsigned long duration = exec_finish_t - exec_start_t;

  if (duration < interval)
    return std::chrono::seconds(interval - duration);

  return std::chrono::seconds(1);
}

} // relay
} // pbote
