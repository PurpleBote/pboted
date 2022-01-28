/**
 * Copyright (c) 2019-2022 polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <netinet/in.h>
#include <utility>

#include "Packet.h"
#include "RelayPeersWorker.h"

namespace pbote
{
namespace relay
{

RelayPeersWorker relay_peers_worker;

RelayPeersWorker::RelayPeersWorker ()
    : started_ (false), m_worker_thread_ (nullptr), task_start_time (0)
{
}

RelayPeersWorker::~RelayPeersWorker () { stop (); }

void
RelayPeersWorker::start ()
{
  started_ = true;
  if (!loadPeers ())
    LogPrint (eLogError, "RelayPeers: have no peers for start");

  std::string loglevel;
  pbote::config::GetOption ("loglevel", loglevel);

  m_worker_thread_
      = new std::thread (std::bind (&RelayPeersWorker::run, this));
}

void
RelayPeersWorker::stop ()
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
RelayPeersWorker::run ()
{
  std::string loglevel;
  pbote::config::GetOption ("loglevel", loglevel);
  while (started_)
    {
      task_start_time
          = std::chrono::system_clock::now ().time_since_epoch ().count ();
      bool task_status = false;
      if (!m_peers_.empty ())
        task_status = checkPeersTask ();
      else
        LogPrint (eLogError, "RelayPeers: have no peers for start");

      unsigned long current_time
          = std::chrono::system_clock::now ().time_since_epoch ().count ();
      unsigned long exec_duration
          = (current_time - task_start_time) / 1000000000;

      unsigned long interval;
      if (task_status)
        {
          interval = UPDATE_INTERVAL_LONG;
          LogPrint (eLogInfo, "RelayPeers: peers lookup success, wait for ",
                    interval / 60, " min.");
        }
      else
        {
          interval = UPDATE_INTERVAL_SHORT;
          LogPrint (eLogWarning,
                    "RelayPeers: no responses, repeat request in ",
                    interval / 60, " min.");
        }

      LogPrint (eLogDebug,
                "RelayPeers: round completed, peers count: ", m_peers_.size (),
                ", duration: ", exec_duration);

      if (exec_duration < interval && interval > 0)
        {
          LogPrint (eLogDebug, "RelayPeers: wait for ",
                    interval - exec_duration, " sec.");
          std::this_thread::sleep_for (
              std::chrono::seconds (interval - exec_duration));
        }
      else
        std::this_thread::sleep_for (std::chrono::seconds (1));
    }
}

bool
RelayPeersWorker::checkPeersTask ()
{
  LogPrint (eLogDebug, "RelayPeers: start new round");
  bool task_status = false;

  auto batch
      = std::make_shared<pbote::PacketBatch<pbote::CommunicationPacket> > ();
  batch->owner = "RelayPeers::main";

  auto peers = getAllPeers ();
  LogPrint (eLogDebug, "RelayPeers: peers.size: ", peers.size ());
  for (const auto &peer : peers)
    {
      // If peer don't sent response we will mark further
      peer->reachable (false);

      auto packet = peerListRequestPacket ();
      PacketForQueue q_packet (peer->ToBase64 (), packet.toByte ().data (),
                               packet.toByte ().size ());

      std::vector<uint8_t> v_cid (std::begin (packet.cid),
                                  std::end (packet.cid));
      batch->addPacket (v_cid, q_packet);
    }

  LogPrint (eLogDebug, "RelayPeers: batch.size: ", batch->packetCount ());
  context.send (batch);

  if (batch->waitLast (UPDATE_INTERVAL_SHORT))
    LogPrint (eLogDebug, "RelayPeers: batch timeout or got last");

  std::vector<std::shared_ptr<pbote::CommunicationPacket> > responses
      = batch->getResponses ();

  if (!responses.empty ())
    {
      task_status = true;
      for (const auto &response : responses)
        {
          if (response->type != type::CommN)
            {
              // ToDo: looks like in case if we got request to ourself, for now
              // we just skip it
              LogPrint (eLogWarning,
                        "RelayPeers: got non-response packet in batch, type: ",
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
              LogPrint (eLogWarning, "RelayPeers: response status: ",
                        statusToString (status));
              continue;
            }

          if (dataLen < 4)
            {
              LogPrint (eLogWarning,
                        "RelayPeers: packet without payload, skip parsing");
              continue;
            }

          std::vector<uint8_t> data
              = { response->payload.data () + offset,
                  response->payload.data () + offset + dataLen };

          // ToDo: looks like it can be too slow, need to think how it can be
          // optimized
          LogPrint (eLogDebug, "RelayPeers: type: ", response->type,
                    ", ver: ", unsigned (response->ver));
          if (unsigned (data[1]) == 5
              && (data[0] == (uint8_t)'L' || data[0] == (uint8_t)'P'))
            {
              if (receivePeerListV5 (data.data (), dataLen))
                {
                  /// Increment peer metric back, if we have response
                  for (const auto &m_peer : m_peers_)
                    {
                      if (m_peer.second->ToBase64 () == response->from)
                        {
                          LogPrint (
                              eLogDebug,
                              "RelayPeers: Got response, mark reachable");
                          m_peer.second->reachable (true);
                        }
                    }
                }
            }
          else if (unsigned (data[1]) == 4
                   && (data[0] == (uint8_t)'L' || data[0] == (uint8_t)'P'))
            {
              if (receivePeerListV4 (data.data (), dataLen))
                {
                  /// Increment peer metric back, if we have response
                  for (const auto &m_peer : m_peers_)
                    {
                      if (m_peer.second->ToBase64 () == response->from)
                        {
                          LogPrint (
                              eLogDebug,
                              "RelayPeers: Got response, mark reachable");
                          m_peer.second->reachable (true);
                        }
                    }
                }
            }
          else
            {
              LogPrint (eLogWarning,
                        "RelayPeers: unknown packet version: ", response->ver);
            }
        }
    }
  else
    {
      LogPrint (eLogWarning, "RelayPeers: Have no responses");
    }

  context.removeBatch (batch);
  writePeers ();

  return task_status;
}

bool
RelayPeersWorker::addPeer (const uint8_t *buf, int len)
{
  std::shared_ptr<i2p::data::IdentityEx> identity
      = std::make_shared<i2p::data::IdentityEx> ();
  if (identity->FromBuffer (buf, len))
    return addPeer (identity, PEER_MIN_REACHABILITY);
  return false;
}

bool
RelayPeersWorker::addPeer (const std::string &peer)
{
  std::shared_ptr<i2p::data::IdentityEx> identity
      = std::make_shared<i2p::data::IdentityEx> ();
  if (identity->FromBase64 (peer))
    return addPeer (identity, PEER_MIN_REACHABILITY);
  return false;
}

bool
RelayPeersWorker::addPeer (
    const std::shared_ptr<i2p::data::IdentityEx> &identity, int samples)
{
  if (findPeer (identity->GetIdentHash ()))
    return false;

  auto local_destination = context.getLocalDestination ();
  if (local_destination->GetIdentHash () == identity->GetIdentHash ())
    {
      LogPrint (eLogDebug, "RelayPeers: addPeer: skip local destination");
      return false;
    }

  sp_peer peer = std::make_shared<RelayPeer> (identity->ToBase64 (), samples);

  std::unique_lock<std::mutex> l (m_peers_mutex_);
  return m_peers_
      .insert (std::pair<hash_key, sp_peer> (peer->GetIdentHash (), peer))
      .second;
}

void
RelayPeersWorker::addPeers (const std::vector<sp_peer> &peers)
{
  for (const auto &peer : peers)
    addPeer (peer, peer->getReachability ());
}

sp_peer
RelayPeersWorker::findPeer (const hash_key &ident) const
{
  std::unique_lock<std::mutex> l (m_peers_mutex_);
  auto it = m_peers_.find (ident);
  if (it != m_peers_.end ())
    return it->second;
  else
    return nullptr;
}

std::vector<std::string>
RelayPeersWorker::readPeers ()
{
  std::string peer_file_path = pbote::fs::DataDirPath (PEER_FILE_NAME);
  LogPrint (eLogInfo, "RelayPeers: Read peers from ", peer_file_path);
  std::ifstream peer_file (peer_file_path);

  if (!peer_file.is_open ())
    {
      LogPrint (eLogError, "RelayPeers: Can't open file ", peer_file_path);
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
RelayPeersWorker::loadPeers ()
{
  LogPrint (eLogInfo, "RelayPeers: loadPeers: Load peers from FS");
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
          if (!peer_s.empty ())
            {
              if (peer.FromBase64 (peer_s))
                {
                  peer.setSamples ((size_t)std::stoi (peer_str));
                  LogPrint (eLogDebug, "RelayPeers: loadPeers: peer: ",
                            peer.GetIdentHash ().ToBase64 (),
                            ", samples: ", peer.getReachability ());
                  peers.push_back (std::make_shared<RelayPeer> (peer));
                }
            }
        }
    }

  if (!peers.empty ())
    {
      addPeers (peers);
      LogPrint (eLogInfo, "RelayPeers: Peers loaded: ", peers.size ());
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
          LogPrint (eLogDebug, "RelayPeers: Successfully add node: ",
                    new_peer->ToBase64 ());
        }
      LogPrint (eLogInfo, "RelayPeers: Added peers: ", peers_added);
      return true;
    }
  else
    return false;
}

void
RelayPeersWorker::writePeers ()
{
  LogPrint (eLogInfo, "RelayPeers: save peers to FS");
  std::string peer_file_path = pbote::fs::DataDirPath (PEER_FILE_NAME);
  std::ofstream peer_file (peer_file_path);

  if (!peer_file.is_open ())
    {
      LogPrint (eLogError, "RelayPeers: can't open file ", peer_file_path);
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
      peer_file << peer.second->toString ();
      peer_file << "\n";
    }

  peer_file.close ();
  LogPrint (eLogDebug, "RelayPeers: peers saved to FS");
}

void
RelayPeersWorker::getRandomPeers ()
{
}

std::vector<sp_peer>
RelayPeersWorker::getGoodPeers ()
{
  std::vector<sp_peer> result;

  for (const auto &m_peer : m_peers_)
    {
      if (m_peer.second->getReachability () > PEER_MIN_REACHABILITY)
        result.push_back (m_peer.second);
    }

  return result;
}

std::vector<sp_peer>
RelayPeersWorker::getGoodPeers (uint8_t num)
{
  auto result = getGoodPeers ();

  while (result.size () > num)
    result.pop_back ();

  return result;
}

std::vector<sp_peer>
RelayPeersWorker::getAllPeers ()
{
  std::vector<sp_peer> result;

  for (const auto &m_peer : m_peers_)
    result.push_back (m_peer.second);

  return result;
}

size_t
RelayPeersWorker::getPeersCount ()
{
  return m_peers_.size ();
}

size_t
RelayPeersWorker::get_good_peer_count ()
{
  return getGoodPeers ().size ();
}

bool
RelayPeersWorker::receivePeerListV4 (const uint8_t *buf, size_t len)
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

  LogPrint (eLogDebug, "RelayPeers: receivePeerListV4: type: ", type,
            ", ver: ", unsigned (ver), ", peers: ", peers_count);

  if ((type == (uint8_t)'L' || type == (uint8_t)'P') && ver == (uint8_t)4)
    {
      size_t peers_added = 0, peers_dup = 0;
      for (size_t i = 0; i < peers_count; i++)
        {
          if (offset == len)
            {
              LogPrint (eLogWarning,
                        "RelayPeers: receivePeerListV4: end of packet!");
              break;
            }
          if (offset + 384 > len)
            {
              LogPrint (eLogWarning,
                        "RelayPeers: receivePeerListV4: incomplete packet!");
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
            LogPrint (eLogWarning,
                      "RelayPeers: receivePeerListV4: fail to add peer");
        }
      LogPrint (eLogDebug,
                "RelayPeers: receivePeerListV4: peers: ", peers_count,
                ", added: ", peers_added, ", dup: ", peers_dup);
      return true;
    }
  else
    return false;
}

bool
RelayPeersWorker::receivePeerListV5 (const uint8_t *buf, size_t len)
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

  LogPrint (eLogDebug, "RelayPeers: receivePeerListV5: type: ", type,
            ", ver: ", unsigned (ver), ", peers: ", peers_count);

  if ((type == (uint8_t)'L' || type == (uint8_t)'P') && ver == (uint8_t)5)
    {
      size_t peers_added = 0, peers_dup = 0;
      for (size_t i = 0; i < peers_count; i++)
        {
          if (offset == len)
            {
              LogPrint (eLogError,
                        "RelayPeers: receivePeerListV5: end of packet");
              break;
            }
          if (offset + 384 > len)
            {
              LogPrint (eLogError,
                        "RelayPeers: receivePeerListV5: incomplete packet");
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
                        "RelayPeers: receivePeerListV5: fail to add peer");
            }
        }
      LogPrint (eLogDebug,
                "RelayPeers: receivePeerListV5: peers: ", peers_count,
                ", added: ", peers_added, ", dup: ", peers_dup);
      return true;
    }
  else
    return false;
}

void
RelayPeersWorker::peerListRequestV4 (const std::string &sender,
                                     const uint8_t *cid)
{
  LogPrint (eLogDebug, "RelayPeers: peerListRequestV4: request from: ",
            sender.substr (0, 15), "...");
  if (addPeer (sender))
    {
      LogPrint (eLogDebug,
                "RelayPeers: peerListRequestV4: add requester to peers list");
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
  LogPrint (eLogInfo, "RelayPeers: peerListRequestV4: send response with ",
            peer_list.count, " peer(s)");
}

void
RelayPeersWorker::peerListRequestV5 (const std::string &sender,
                                     const uint8_t *cid)
{
  LogPrint (eLogDebug, "RelayPeers: peerListRequestV5: request from: ",
            sender.substr (0, 15), "...");

  if (addPeer (sender))
    {
      LogPrint (eLogDebug,
                "RelayPeers: peerListRequestV5: add requester to peers list");
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
  LogPrint (eLogInfo, "RelayPeers: peerListRequestV5: send response with ",
            peer_list.count, " peer(s)");
}

pbote::PeerListRequestPacket
RelayPeersWorker::peerListRequestPacket ()
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

} // relay
} // pbote
