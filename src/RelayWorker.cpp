/**
 * Copyright (C) 2019-2022 polistern
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

RelayWorker::~RelayWorker () { stop (); }

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
  started_ = false;
  if (m_worker_thread_)
    {
      m_worker_thread_->join ();
      delete m_worker_thread_;
      m_worker_thread_ = nullptr;
    }
}

void
RelayWorker::run ()
{
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

      std::this_thread::sleep_for (delay);
    }
}

bool
RelayWorker::check_peers ()
{
  LogPrint (eLogDebug, "Relay: Start new round");

  auto batch
      = std::make_shared<pbote::PacketBatch<pbote::CommunicationPacket> > ();
  batch->owner = "relay::main";

  auto peers = getAllPeers ();
  LogPrint (eLogDebug, "Relay: Peers count: ", peers.size ());
  for (const auto &peer : peers)
    {
      // If peer responde we will mark further
      peer->reachable (false);

      auto packet = peerListRequestPacket ();
      PacketForQueue q_packet (peer->ToBase64 (), packet.toByte ().data (),
                               packet.toByte ().size ());

      std::vector<uint8_t> v_cid (std::begin (packet.cid),
                                  std::end (packet.cid));
      batch->addPacket (v_cid, q_packet);
    }

  LogPrint (eLogDebug, "Relay: Batch size: ", batch->packetCount ());
  context.send (batch);

  if (batch->waitLast (RELAY_CHECK_TIMEOUT))
    LogPrint (eLogDebug, "Relay: Batch timed out or got last");

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

      size_t offset = 0;
      uint8_t status = 0;
      uint16_t dataLen = 0;

      std::memcpy (&status, response->payload.data (), 1);
      offset += 1;
      std::memcpy (&dataLen, response->payload.data () + offset, 2);
      dataLen = ntohs (dataLen);
      offset += 2;

      if (status != StatusCode::OK)
        {
          LogPrint (eLogWarning, "Relay: Response: ", statusToString (status));
          continue;
        }

      if (dataLen < 4)
        {
          LogPrint (eLogWarning,
                    "Relay: Packet without payload, parsing skipped");
          continue;
        }

      std::vector<uint8_t> data
          = { response->payload.data () + offset,
              response->payload.data () + offset + dataLen };

      // ToDo: looks like it can be too slow, need to think how to optimized it
      LogPrint (eLogDebug, "Relay: type: ", response->type,
                ", ver: ", unsigned (response->ver));

      if (unsigned (data[1]) == 5
          && (data[0] == (uint8_t)'L' || data[0] == (uint8_t)'P'))
        {
          if (!receivePeerListV5 (data.data (), dataLen))
            {
              LogPrint (eLogWarning, "Relay: Can't parse packet");
              continue;
            }
          /// Increment peer metric back, if we have response
          for (const auto &m_peer : m_peers_)
            {
              if (m_peer.second->ToBase64 () == response->from)
                {
                  LogPrint (eLogDebug, "Relay: Got response, mark reachable");
                  m_peer.second->reachable (true);
                }
            }
        }
      else if (unsigned (data[1]) == 4
               && (data[0] == (uint8_t)'L' || data[0] == (uint8_t)'P'))
        {
          if (!receivePeerListV4 (data.data (), dataLen))
            {
              LogPrint (eLogWarning, "Relay: Can't parse packet");
              continue;
            }
              /// Increment peer metric back, if we have response
          for (const auto &m_peer : m_peers_)
            {
              if (m_peer.second->ToBase64 () == response->from)
                {
                  LogPrint (eLogDebug, "Relay: Got response, mark reachable");
                  m_peer.second->reachable (true);
                }
            }
        }
      else
        {
          LogPrint (eLogWarning, "Relay: Unknown version: ", response->ver);
        }
    }

  context.removeBatch (batch);
  writePeers ();

  return true;
}

bool
RelayWorker::addPeer (const uint8_t *buf, int len)
{
  std::shared_ptr<i2p::data::IdentityEx> identity
      = std::make_shared<i2p::data::IdentityEx> ();

  if (identity->FromBuffer (buf, len))
    return addPeer (identity, PEER_MIN_REACHABILITY);

  return false;
}

bool
RelayWorker::addPeer (const std::string &peer)
{
  std::shared_ptr<i2p::data::IdentityEx> identity
      = std::make_shared<i2p::data::IdentityEx> ();

  if (identity->FromBase64 (peer))
    return addPeer (identity, PEER_MIN_REACHABILITY);

  return false;
}

bool
RelayWorker::addPeer (
    const std::shared_ptr<i2p::data::IdentityEx> &identity, int samples)
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
          std::shared_ptr<i2p::data::IdentityEx> new_peer
              = std::make_shared<i2p::data::IdentityEx> ();

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
  peer_file << "#   samp = samples from 0 to 25, depending on whether the "
               "peer responded\n";
  peer_file << "# The fields are separated by a space character.\n";
  peer_file << "# Lines starting with a # are ignored.\n";
  peer_file << "# Do not edit this file while pbote is running as it will be "
               "overwritten.\n\n";

  for (const auto &peer : m_peers_)
    {
      peer_file << peer.second->str ();
      peer_file << "\n";
    }

  peer_file.close ();
  LogPrint (eLogDebug, "Relay: Peers saved to FS");
}

void
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

bool
RelayWorker::receivePeerListV4 (const uint8_t *buf, size_t len)
{
  size_t offset = 0;
  uint8_t type, ver;
  uint16_t peers_count;

  std::memcpy (&type, buf, 1);
  offset += 1;
  std::memcpy (&ver, buf + offset, 1);
  offset += 1;
  std::memcpy (&peers_count, buf + offset, 2);
  offset += 2;
  peers_count = ntohs (peers_count);

  LogPrint (eLogDebug, "Relay: receivePeerListV4: type: ", type,
            ", ver: ", unsigned (ver), ", peers: ", peers_count);

  if ((type == (uint8_t)'L' || type == (uint8_t)'P') && ver == (uint8_t)4)
    {
      size_t peers_added = 0, peers_dup = 0;
      for (size_t i = 0; i < peers_count; i++)
        {
          if (offset == len)
            {
              LogPrint (eLogWarning, "Relay: receivePeerListV4: End of packet");
              break;
            }
          if (offset + 384 > len)
            {
              LogPrint (eLogWarning,
                        "Relay: receivePeerListV4: Incomplete packet");
              break;
            }

          uint8_t fullKey[387];
          memcpy (fullKey, buf + offset, 384);
          offset += 384;

          i2p::data::IdentityEx peer;

          /// This is an ugly workaround, but the 4th version of the protocol
          /// does not allow the correct key type to be determined
          fullKey[384] = 0;
          fullKey[385] = 0;
          fullKey[386] = 0;

          size_t res = peer.FromBuffer (fullKey, 387);
          if (res > 0)
            {
              if (addPeer (fullKey, 387))
                peers_added++;
              else
                peers_dup++;
            }
          else
            LogPrint (eLogWarning, "Relay: receivePeerListV4: Fail to add peer");
        }
      LogPrint (eLogDebug,
                "Relay: receivePeerListV4: peers: ", peers_count,
                ", added: ", peers_added, ", dup: ", peers_dup);
      return true;
    }
  else
    return false;
}

bool
RelayWorker::receivePeerListV5 (const uint8_t *buf, size_t len)
{
  size_t offset = 0;
  uint8_t type, ver;
  uint16_t peers_count;

  std::memcpy (&type, buf, 1);
  offset += 1;
  std::memcpy (&ver, buf + offset, 1);
  offset += 1;
  std::memcpy (&peers_count, buf + offset, 2);
  offset += 2;
  peers_count = ntohs (peers_count);

  LogPrint (eLogDebug, "Relay: receivePeerListV5: type: ", type,
            ", ver: ", unsigned (ver), ", peers: ", peers_count);

  if ((type == (uint8_t)'L' || type == (uint8_t)'P') && ver == (uint8_t)5)
    {
      size_t peers_added = 0, peers_dup = 0;
      for (size_t i = 0; i < peers_count; i++)
        {
          if (offset == len)
            {
              LogPrint (eLogError,
                        "Relay: receivePeerListV5: End of packet");
              break;
            }
          if (offset + 384 > len)
            {
              LogPrint (eLogError,
                        "Relay: receivePeerListV5: Incomplete packet");
              break;
            }

          std::shared_ptr<i2p::data::IdentityEx> peer
              = std::make_shared<i2p::data::IdentityEx> ();

          size_t key_len = peer->FromBuffer (buf + offset, len - offset);
          offset += key_len;

          if (key_len > 0)
            {
              if (addPeer (peer->ToBase64 ()))
                peers_added++;
              else
                peers_dup++;
            }
          else
            {
              LogPrint (eLogWarning,
                        "Relay: receivePeerListV5: Fail to add peer");
            }
        }
      LogPrint (eLogDebug,
                "Relay: receivePeerListV5: peers: ", peers_count,
                ", added: ", peers_added, ", dup: ", peers_dup);
      return true;
    }
  else
    return false;
}

void
RelayWorker::peerListRequestV4 (const std::string &sender, const uint8_t *cid)
{
  LogPrint (eLogDebug, "Relay: peerListRequestV4: request from: ",
            sender.substr (0, 15), "...");
  if (addPeer (sender))
    {
      LogPrint (eLogDebug,
                "Relay: peerListRequestV4: Requester added to peers list");
    }

  auto good_peers = getGoodPeers (MAX_PEERS_TO_SEND);
  pbote::PeerListPacketV4 peer_list;
  peer_list.count = good_peers.size ();

  for (const auto &peer : good_peers)
    {
      uint8_t *buf = new uint8_t[peer->GetFullLen ()];
      size_t l = peer->ToBuffer (buf, peer->GetFullLen ());
      if (l > 0)
        peer_list.data.insert (peer_list.data.end (), buf, buf + l);
      delete[] buf;
    }

  pbote::ResponsePacket response;
  memcpy (response.cid, cid, 32);
  response.status = StatusCode::OK;
  response.data = peer_list.toByte ();
  response.length = response.data.size ();
  auto data = response.toByte ();

  context.send (PacketForQueue (sender, data.data (), data.size ()));
  LogPrint (eLogInfo, "Relay: peerListRequestV4: Send response with ",
            peer_list.count, " peer(s)");
}

void
RelayWorker::peerListRequestV5 (const std::string &sender, const uint8_t *cid)
{
  LogPrint (eLogDebug, "Relay: peerListRequestV5: Request from: ",
            sender.substr (0, 15), "...");

  if (addPeer (sender))
    {
      LogPrint (eLogDebug,
                "Relay: peerListRequestV5: Requester added to peers list");
    }

  auto good_peers = getGoodPeers (MAX_PEERS_TO_SEND);
  pbote::PeerListPacketV5 peer_list;
  peer_list.count = good_peers.size ();

  for (const auto &peer : good_peers)
    {
      uint8_t *buf = new uint8_t[peer->GetFullLen ()];
      size_t l = peer->ToBuffer (buf, peer->GetFullLen ());
      if (l > 0)
        peer_list.data.insert (peer_list.data.end (), buf, buf + l);
      delete[] buf;
    }

  pbote::ResponsePacket response;
  memcpy (response.cid, cid, 32);
  response.status = StatusCode::OK;
  response.data = peer_list.toByte ();
  response.length = response.data.size ();
  auto data = response.toByte ();

  context.send (PacketForQueue (sender, data.data (), data.size ()));
  LogPrint (eLogInfo, "Relay: peerListRequestV5: Send response with ",
            peer_list.count, " peer(s)");
}

pbote::PeerListRequestPacket
RelayWorker::peerListRequestPacket ()
{
  /// don't reuse request packets because PacketBatch will not
  /// add the same one more than once
  pbote::PeerListRequestPacket packet;

  /// Java will be answer with v4, pboted - with v5,
  /// so we can determine who is who
  packet.ver = 5;
  context.random_cid (packet.cid, 32);
  return packet;
}

void
RelayWorker::set_start_time ()
{
  auto current_time = std::chrono::system_clock::now ();
  auto current_epoch = current_time.time_since_epoch ();
  auto current_sec =
    std::chrono::duration_cast<std::chrono::seconds> (current_epoch);
  exec_start_t = current_sec.count ();
}

void
RelayWorker::set_finish_time ()
{
  auto current_time = std::chrono::system_clock::now ();
  auto current_epoch = current_time.time_since_epoch ();
  auto current_sec =
    std::chrono::duration_cast<std::chrono::seconds> (current_epoch);
  exec_finish_t = current_sec.count ();
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
