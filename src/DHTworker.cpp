/**
 * Copyright (C) 2019-2022, polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <mutex>
#include <thread>

#include "BoteContext.h"
#include "DHTworker.h"
#include "Packet.h"

namespace pbote
{
namespace kademlia
{

DHTworker DHT_worker;

DHTworker::DHTworker ()
    : started_ (false), m_worker_thread_ (nullptr), local_node_ (nullptr)
{
}

DHTworker::~DHTworker ()
{
  stop ();

  if (m_worker_thread_)
    {
      m_worker_thread_->join ();
      delete m_worker_thread_;
      m_worker_thread_ = nullptr;
    }
}

void
DHTworker::start ()
{
  local_node_
      = std::make_shared<Node> (context.getLocalDestination ()->ToBase64 ());
  if (isStarted ())
    return;

  if (!loadNodes ())
    LogPrint (eLogWarning, "DHT: Have no nodes for start");

  LogPrint (eLogDebug, "DHT: Load local packets");
  dht_storage_.set_storage_limit ();
  dht_storage_.update ();

  started_ = true;
  m_worker_thread_ = new std::thread (std::bind (&DHTworker::run, this));
}

void
DHTworker::stop ()
{
  if (!isStarted ())
    return;

  started_ = false;

  LogPrint (eLogWarning, "DHT: Stopped");
}

bool
DHTworker::addNode (const std::string &dest)
{
  i2p::data::IdentityEx identity;
  if (identity.FromBase64 (dest))
    {
      return addNode (identity);
    }
  else
    {
      LogPrint (eLogDebug, "DHT: addNode: Can't create node from base64");
      return false;
    }
}

bool
DHTworker::addNode (const uint8_t *buf, size_t len)
{
  i2p::data::IdentityEx identity;
  if (identity.FromBuffer (buf, len))
    return addNode (identity);
  else
    {
      LogPrint (eLogWarning, "DHT: addNode: Can't create node from buffer");
      return false;
    }
}

bool
DHTworker::addNode (const i2p::data::IdentityEx &identity)
{
  if (findNode (identity.GetIdentHash ()))
    return false;

  auto local_destination = context.getLocalDestination ();
  if (*local_destination == identity)
    {
      LogPrint (eLogDebug, "DHT: addNode: Local destination, skipped");
      return false;
    }

  auto node = std::make_shared<Node> ();
  node->FromBase64 (identity.ToBase64 ());
  std::unique_lock<std::mutex> l (m_nodes_mutex_);
  return m_nodes_
      .insert (std::pair<HashKey, sp_node> (node->GetIdentHash (), node))
      .second;
}

sp_node
DHTworker::findNode (const HashKey &ident) const
{
  std::unique_lock<std::mutex> l (m_nodes_mutex_);
  auto it = m_nodes_.find (ident);
  if (it != m_nodes_.end ())
    return it->second;
  else
    return nullptr;
}

sp_node
DHTworker::getClosestNode (const HashKey &key, bool to_us)
{
  return getClosestNodes (key, 1, to_us)[0];
}

std::vector<sp_node>
DHTworker::getClosestNodes (HashKey key, size_t num, bool to_us)
{
  struct sortable_node
  {
    sp_node node;
    i2p::data::XORMetric metric;
    bool
    operator< (const sortable_node &other) const
    {
      return metric < other.metric;
    };
  };

  LogPrint (eLogDebug, "DHT: getClosestNodes: key: ", key.ToBase64 (),
            ", num: ", num, ", to_us: ", to_us ? "true" : "false");

  std::set<sortable_node> sorted_nodes;

  i2p::data::XORMetric our_metric;
  if (to_us)
    our_metric = key ^ local_node_->GetIdentHash ();

  {
    std::unique_lock<std::mutex> l (m_nodes_mutex_);
    for (const auto &it : m_nodes_)
      {
        if (it.second->locked ())
          continue;
        /// Distance - XOR result for two hashes.
        /// Will be than larger, the more they differ.
        /// We are interested in the minimum difference (distance).
        i2p::data::XORMetric metric = key ^ it.second->GetIdentHash ();

        if (to_us && our_metric < metric)
          continue;

        if (sorted_nodes.size () < num)
          sorted_nodes.insert ({ it.second, metric });
        else if (metric < sorted_nodes.rbegin ()->metric)
          {
            /// If current metric less than biggest in sorted node
            ///   add current and remove one from the end
            sorted_nodes.insert ({ it.second, metric });
            sorted_nodes.erase (std::prev (sorted_nodes.end ()));
          }
      }
  }

  std::vector<sp_node> result;
  size_t i = 0;
  for (const auto &it : sorted_nodes)
    {
      if (i >= num)
        break;

      /// For debug only
      /*
      std::stringstream ss;
      for (int k = 0;k<3;k++)
        ss << std::setw(3) << std::setfill('0') << unsigned(it.metric.metric[k]);

      LogPrint (eLogDebug, "DHT: getClosestNodes: node: ",
                it.node->GetIdentHash ().ToBase32 (), ", metric: ", ss.str());
      */

      result.push_back (it.node);
      i++;
    }

  return result;
}

std::vector<sp_node>
DHTworker::getAllNodes ()
{
  std::vector<sp_node> result;

  for (const auto &node : m_nodes_)
    result.push_back (node.second);

  return result;
}

std::vector<sp_node>
DHTworker::getUnlockedNodes ()
{
  std::vector<sp_node> res;
  std::unique_lock<std::mutex> l (m_nodes_mutex_);

  for (const auto &it : m_nodes_)
    {
      if (!it.second->locked ())
        {
          res.push_back (it.second);
        }
    }

  return res;
}

std::vector<sp_comm_pkt>
DHTworker::findOne (HashKey hash, uint8_t type)
{
  return find (hash, type, false);
}

std::vector<sp_comm_pkt>
DHTworker::findAll (HashKey hash, uint8_t type)
{
  return find (hash, type, true);
}

std::vector<sp_comm_pkt>
DHTworker::find (HashKey key, uint8_t type, bool exhaustive)
{
  LogPrint (eLogDebug, "DHT: find: Start for type: ", type,
            ", key: ", key.ToBase64 ());

  auto batch = std::make_shared<batch_comm_packet> ();
  batch->owner = "DHT::find";

  std::vector<sp_node> closestNodes = closestNodesLookupTask (key);

  // ToDo: add find locally

  LogPrint (eLogDebug,
            "DHT: find: Closest nodes count: ", closestNodes.size ());

  if (closestNodes.size () < MIN_CLOSEST_NODES)
    {
      LogPrint (eLogInfo, "DHT: find: Not enough nodes, try usual nodes");

      for (const auto &node : m_nodes_)
        closestNodes.push_back (node.second);

      LogPrint (eLogDebug, "DHT: find: Usual nodes: ", closestNodes.size ());
    }

  if (closestNodes.empty ())
    {
      LogPrint (eLogError, "DHT: find: Not enough nodes");
      return {};
    }

  for (const auto &node : closestNodes)
    {
      auto packet = retrieveRequestPacket (type, key);

      PacketForQueue q_packet (node->ToBase64 (), packet.toByte ().data (),
                               packet.toByte ().size ());

      std::vector<uint8_t> v_cid (std::begin (packet.cid),
                                  std::end (packet.cid));
      batch->addPacket (v_cid, q_packet);
    }

  LogPrint (eLogDebug, "DHT: find: Batch size: ", batch->packetCount ());
  context.send (batch);

  if (exhaustive)
    batch->waitLast (RESPONSE_TIMEOUT);
  else
    batch->waitFist (RESPONSE_TIMEOUT);

  int counter = 0;

  while (batch->responseCount () < 1 && counter < 5)
    {
      LogPrint (eLogWarning, "DHT: find: No responses, resend: #", counter);
      context.removeBatch (batch);
      context.send (batch);

      if (exhaustive)
        batch->waitLast (RESPONSE_TIMEOUT);
      else
        batch->waitFist (RESPONSE_TIMEOUT);
      counter++;
    }

  LogPrint (eLogDebug, "DHT: find: Got ", batch->responseCount (),
            " responses for ", key.ToBase64 (), ", type: ", type);

  context.removeBatch (batch);
  auto responses = batch->getResponses ();

  std::vector<sp_comm_pkt> result;
  result.reserve (responses.size ());

  for (const auto &response : responses)
    {
      ResponsePacket response_packet;
      bool parsed = response_packet.from_comm_packet (*response, true);
      if (!parsed)
        {
          LogPrint (eLogWarning, "DHT: find: Can't parse response");
          continue;
        }

      LogPrint (eLogDebug, "DHT: find: Response status ",
                statusToString (response_packet.status));

      if (response_packet.status == StatusCode::OK)
        result.push_back (response);
    }

  LogPrint (eLogDebug, "DHT: find: Got ", result.size (), " valid responses");

  return result;
}

std::vector<std::string>
DHTworker::store (HashKey hash, uint8_t type, pbote::StoreRequestPacket packet)
{
  LogPrint (eLogDebug, "DHT: store: Start for type: ", type,
            ", key: ", hash.ToBase64 ());

  auto batch = std::make_shared<batch_comm_packet> ();
  batch->owner = "DHT::store";

  std::vector<sp_node> closestNodes = closestNodesLookupTask (hash);

  LogPrint (eLogDebug, "DHT: store: Closest nodes: ", closestNodes.size ());

  if (closestNodes.size () < MIN_CLOSEST_NODES)
    {
      LogPrint (eLogWarning, "DHT: store: Not enough nodes, try usual nodes");

      for (const auto &node : m_nodes_)
        closestNodes.push_back (node.second);

      LogPrint (eLogDebug, "DHT: store: Usual nodes: ", closestNodes.size ());
    }

  if (closestNodes.empty ())
    {
      LogPrint (eLogError, "DHT: store: Not enough nodes");
      return {};
    }

  for (const auto &node : closestNodes)
    {
      context.random_cid (packet.cid, 32);
      auto packet_bytes = packet.toByte ();
      PacketForQueue q_packet (node->ToBase64 (), packet_bytes.data (),
                               packet_bytes.size ());

      std::vector<uint8_t> v_cid (std::begin (packet.cid),
                                  std::end (packet.cid));
      batch->addPacket (v_cid, q_packet);
    }

  LogPrint (eLogDebug, "DHT: store: Batch size: ", batch->packetCount ());

  context.send (batch);
  batch->waitLast (RESPONSE_TIMEOUT);

  int counter = 0;

  // ToDo:
  //while (batch->responseCount () < KADEMLIA_CONSTANT_K && counter <= 5)
  while (batch->responseCount () < 2 && counter <= 5)
    {
      LogPrint (eLogWarning, "DHT: store: No responses, resend: #", counter);
      context.removeBatch (batch);
      context.send (batch);

      batch->waitLast (RESPONSE_TIMEOUT);
      counter++;
    }

  LogPrint (eLogDebug, "DHT: store: Got ", batch->responseCount (),
            " responses for ", hash.ToBase64 (), ", type: ", type);

  context.removeBatch (batch);
  auto responses = batch->getResponses ();

  std::vector<std::string> result;
  result.reserve (responses.size ());

  for (const auto &response : responses)
    {
      ResponsePacket response_packet;
      bool parsed = response_packet.from_comm_packet (*response, true);
      if (!parsed)
        {
          LogPrint (eLogWarning, "DHT: store: Can't parse response");
          continue;
        }

      LogPrint (eLogDebug, "DHT: store: Response status ",
                statusToString (response_packet.status));

      if (response_packet.status == StatusCode::OK ||
          response_packet.status == StatusCode::DUPLICATED_DATA)
        {
          result.push_back (response->from);
        }
    }

  LogPrint (eLogDebug, "DHT: store: Got ", result.size (), " valid responses");

  return result;
}

std::vector<std::string>
DHTworker::deleteEmail (HashKey hash, uint8_t type,
                        pbote::EmailDeleteRequestPacket packet)
{
  LogPrint (eLogDebug, "DHT: deleteEmail: Start for type: ", type,
            ", hash: ", hash.ToBase64 ());

  if (dht_storage_.deleteEmail (hash))
    {
      LogPrint (eLogDebug, "DHT: deleteEmail: Removed local packet, hash: ",
        hash.ToBase64 ());
    }

  auto batch = std::make_shared<batch_comm_packet> ();
  batch->owner = "DHT::deleteEmail";

  std::vector<sp_node> closestNodes = closestNodesLookupTask (hash);

  LogPrint (eLogDebug,
            "DHT: deleteEmail: Closest nodes: ", closestNodes.size ());

  if (closestNodes.size () < MIN_CLOSEST_NODES)
    {
      LogPrint (eLogInfo,
                "DHT: deleteEmail: Not enough nodes, try usual nodes");

      for (const auto &node : m_nodes_)
        closestNodes.push_back (node.second);

      LogPrint (eLogDebug,
                "DHT: deleteEmail: Usual nodes: ", closestNodes.size ());

      if (closestNodes.size () < MIN_CLOSEST_NODES)
        {
          LogPrint (eLogWarning, "DHT: deleteEmail: Not enough nodes");
          return {};
        }
    }

  for (const auto &node : closestNodes)
    {
      context.random_cid (packet.cid, 32);
      auto packet_bytes = packet.toByte ();
      PacketForQueue q_packet (node->ToBase64 (), packet_bytes.data (),
                               packet_bytes.size ());

      std::vector<uint8_t> v_cid (std::begin (packet.cid),
                                  std::end (packet.cid));
      batch->addPacket (v_cid, q_packet);
    }

  LogPrint (eLogDebug,
            "DHT: deleteEmail: Batch size: ", batch->packetCount ());
  context.send (batch);

  batch->waitLast (RESPONSE_TIMEOUT);

  int counter = 0;
  while (batch->responseCount () < 1 && counter <= 5)
    {
      LogPrint (eLogWarning, "DHT: deleteEmail: No responses, resend: #",
                counter);
      context.removeBatch (batch);
      context.send (batch);
      // ToDo: remove answered nodes from batch
      batch->waitLast (RESPONSE_TIMEOUT);
      counter++;
    }

  LogPrint (eLogDebug, "DHT: deleteEmail: Got ", batch->responseCount (),
            " responses for ", hash.ToBase64 (), ", type: ", type);
  context.removeBatch (batch);

  std::vector<std::string> res;

  auto responses = batch->getResponses ();

  res.reserve (responses.size ());
  for (const auto &response : responses)
    {
      pbote::ResponsePacket res_packet;
      res_packet.from_comm_packet (*response, true);

      if (res_packet.status == StatusCode::OK ||
          res_packet.status == StatusCode::NO_DATA_FOUND)
        {
          res.push_back (response->from);
          LogPrint (eLogDebug, "DHT: deleteEmail: Valid response from: ",
                    response->from.substr (0, 15), "...");
        }
    }

  return res;
}

std::vector<std::string>
DHTworker::deleteIndexEntry (HashKey index_dht_key, HashKey email_dht_key,
                             HashKey del_auth)
{
  LogPrint (eLogDebug, "DHT: deleteIndexEntry: Start for key: ",
            email_dht_key.ToBase64 (), ", hash: ", del_auth.ToBase64 ());

  // ToDo: Need to check if we need to remove part
  if (dht_storage_.deleteIndex (index_dht_key))
    {
      LogPrint (eLogDebug,
        "DHT: deleteIndexEntry: Removed local packet, hash: ",
        index_dht_key.ToBase64 ());
    }

  auto batch = std::make_shared<batch_comm_packet> ();
  batch->owner = "DHT::deleteIndexEntry";

  std::vector<sp_node> closestNodes = closestNodesLookupTask (index_dht_key);

  LogPrint (eLogDebug,
            "DHT: deleteIndexEntry: Closest nodes: ", closestNodes.size ());

  if (closestNodes.size () < MIN_CLOSEST_NODES)
    {
      LogPrint (eLogInfo,
                "DHT: deleteIndexEntry: Not enough nodes, try usual nodes");

      for (const auto &node : m_nodes_)
        closestNodes.push_back (node.second);

      LogPrint (eLogDebug,
                "DHT: deleteIndexEntry: Usual nodes: ", closestNodes.size ());
    }

  if (closestNodes.empty ())
    {
      LogPrint (eLogWarning, "DHT: deleteIndexEntry: Not enough nodes");
      return {};
    }

  for (const auto &node : closestNodes)
    {
      pbote::IndexDeleteRequestPacket packet;
      context.random_cid (packet.cid, 32);

      memcpy (packet.dht_key, index_dht_key.data (), 32);
      packet.count = 1;
      pbote::IndexDeleteRequestPacket::item item;
      memcpy (item.key, email_dht_key.data (), 32);
      memcpy (item.da, del_auth.data (), 32);

      packet.data.push_back (item);

      auto packet_bytes = packet.toByte ();
      PacketForQueue q_packet (node->ToBase64 (), packet_bytes.data (),
                               packet_bytes.size ());

      std::vector<uint8_t> v_cid (std::begin (packet.cid),
                                  std::end (packet.cid));
      batch->addPacket (v_cid, q_packet);
    }

  LogPrint (eLogDebug,
            "DHT: deleteIndexEntry: Batch size: ", batch->packetCount ());

  context.send (batch);

  batch->waitLast (RESPONSE_TIMEOUT);

  int counter = 0;
  while (batch->responseCount () < 1 && counter < 5)
    {
      LogPrint (eLogWarning, "DHT: deleteIndexEntry: No responses, resend: #",
                counter);
      context.removeBatch (batch);
      context.send (batch);
      // ToDo: remove answered nodes from batch
      batch->waitLast (RESPONSE_TIMEOUT);
      counter++;
    }

  LogPrint (eLogDebug, "DHT: deleteIndexEntry: Got ", batch->responseCount (),
            " responses for key ", email_dht_key.ToBase64 ());

  context.removeBatch (batch);

  std::vector<std::string> res;

  auto responses = batch->getResponses ();

  for (const auto &response : responses)
    {
      pbote::ResponsePacket res_packet;
      res_packet.from_comm_packet (*response, true);

      if (res_packet.status == StatusCode::OK ||
          res_packet.status == StatusCode::NO_DATA_FOUND)
        {
          res.push_back (response->from);
          LogPrint (eLogDebug, "DHT: deleteIndexEntry: Valid response from: ",
                    response->from.substr (0, 15), "...");
        }
    }

  return res;
}

std::vector<std::shared_ptr<pbote::DeletionInfoPacket> >
DHTworker::deletion_query (const HashKey &key)
{
  LogPrint (eLogDebug, "DHT: deletion_query: Start for key: ", key.ToBase64 ());

  // ToDo: Need to check if we have localy
  /*
  if (dht_storage_.get_del_info (key))
    {
      LogPrint (eLogDebug, "DHT: deletion_query: Removed local DelInfo, key: ",
                key.ToBase64 ());
    }
  */

  auto batch = std::make_shared<batch_comm_packet> ();
  batch->owner = "DHT::deletion_query";

  std::vector<sp_node> close_nodes = closestNodesLookupTask (key);

  LogPrint (eLogDebug, "DHT: deletion_query: Closest nodes: ",
            close_nodes.size ());

  if (close_nodes.size () < MIN_CLOSEST_NODES)
    {
      LogPrint (eLogInfo,
                "DHT: deletion_query: Not enough nodes, try usual nodes");

      for (const auto &node : m_nodes_)
        close_nodes.push_back (node.second);

      LogPrint (eLogDebug,
                "DHT: deletion_query: Usual nodes: ", close_nodes.size ());
    }

  if (close_nodes.empty ())
    {
      LogPrint (eLogWarning, "DHT: deletion_query: Not enough nodes");
      return {};
    }

  for (const auto &node : close_nodes)
    {
      pbote::DeletionQueryPacket packet;
      context.random_cid (packet.cid, 32);
      memcpy (packet.dht_key, key.data (), 32);

      auto packet_bytes = packet.toByte ();
      PacketForQueue q_packet (node->ToBase64 (), packet_bytes.data (),
                               packet_bytes.size ());

      std::vector<uint8_t> v_cid (std::begin (packet.cid),
                                  std::end (packet.cid));
      batch->addPacket (v_cid, q_packet);
    }

  LogPrint (eLogDebug,
            "DHT: deletion_query: Batch size: ", batch->packetCount ());

  context.send (batch);

  batch->waitLast (RESPONSE_TIMEOUT);

  int counter = 0;
  while (batch->responseCount () < 1 && counter < 5)
    {
      LogPrint (eLogWarning, "DHT: deletion_query: No responses, resend: #",
                counter);
      context.removeBatch (batch);
      context.send (batch);
      // ToDo: remove answered nodes from batch
      batch->waitLast (RESPONSE_TIMEOUT);
      counter++;
    }

  LogPrint (eLogDebug, "DHT: deletion_query: Got ", batch->responseCount (),
            " responses for key ", key.ToBase64 ());

  context.removeBatch (batch);

  std::vector<std::shared_ptr<pbote::DeletionInfoPacket> > results;

  auto responses = batch->getResponses ();

  for (const auto &response : responses)
    {
      pbote::ResponsePacket res_packet;
      res_packet.from_comm_packet (*response, true);

      if (res_packet.status == StatusCode::OK)
        {
          LogPrint (eLogDebug, "DHT: deletion_query: OK response from: ",
                    response->from.substr (0, 15), "...");

          pbote::DeletionInfoPacket del_info_packet;
          del_info_packet.fromBuffer (res_packet.data, true);
          results.push_back (std::make_shared<pbote::DeletionInfoPacket>(del_info_packet));
        }
    }

  LogPrint (eLogDebug, "DHT: deletion_query: Got ", results.size (),
            " results for key ", key.ToBase64 ());

  return results;
}

std::vector<sp_node>
DHTworker::closestNodesLookupTask (HashKey key)
{
  auto batch = std::make_shared<batch_comm_packet> ();
  batch->owner = "DHT::closestNodesLookup";

  std::map<HashKey, sp_node> closestNodes;
  std::vector<sp_comm_pkt> responses;
  std::map<std::vector<uint8_t>, sp_node> active_requests;

  /// Set start time
  auto task_start_time
      = std::chrono::system_clock::now ().time_since_epoch ().count ();
  auto unlocked_nodes = getUnlockedNodes ();

  if (unlocked_nodes.empty ())
    unlocked_nodes = getAllNodes ();

  for (auto node : unlocked_nodes)
    {
      /// Create find closest peers packet
      auto packet = findClosePeersPacket (key);
      auto bytes = packet.toByte ();

      PacketForQueue q_packet (node->ToBase64 (), bytes.data (), bytes.size ());
      std::vector<uint8_t> vcid (std::begin (packet.cid), std::end (packet.cid));

      /// Copy packet to pending task for check timeout later
      active_requests.insert (
          std::pair<std::vector<uint8_t>, sp_node> (vcid, node));
      batch->addPacket (vcid, q_packet);
    }

  unsigned long current_time
      = std::chrono::system_clock::now ().time_since_epoch ().count ();
  unsigned long exec_duration = (current_time - task_start_time) / 1000000000;
  size_t counter = 1;

  /// While we have unanswered requests and timeout not reached
  while (!active_requests.empty ()
         && exec_duration < CLOSEST_NODES_LOOKUP_TIMEOUT)
    {
      LogPrint (eLogDebug, "DHT: closestNodesLookup: Request #", counter);
      LogPrint (eLogDebug, "DHT: closestNodesLookup: Batch size: ",
                batch->packetCount ());

      context.send (batch);
      batch->waitLast (RESPONSE_TIMEOUT);
      context.removeBatch (batch);
      responses = batch->getResponses ();

      if (responses.empty ())
        {
          LogPrint (eLogWarning, "DHT: closestNodesLookup: Not enough "
                                 "responses, resend batch");
          continue;
        }

      LogPrint (eLogDebug, "DHT: closestNodesLookup: Got ",responses.size (),
                " responses for key ", key.ToBase64 ());

      for (const auto &response : responses)
        {
          std::vector<uint8_t> vcid (std::begin (response->cid),
                                     std::end (response->cid));
          /// Check if we sent requests with this CID
          if (active_requests.find (vcid) != active_requests.end ())
            {
              /// Remove node from active requests and from batch
              active_requests.erase (vcid);
              batch->removePacket (vcid);
            }
        }

      current_time
          = std::chrono::system_clock::now ().time_since_epoch ().count ();
      exec_duration = (current_time - task_start_time) / 1000000000;
      counter++;
    }

  context.removeBatch (batch);

  /// If we have at least one response
  for (const auto &response : responses)
    {
      if (response->type != type::CommN)
        {
          // ToDo: Looks like in case if we got request to ourself,
          // for now we just skip it
          LogPrint (eLogWarning,
                    "DHT: closestNodesLookup: Got non-response packet, type: ",
                    response->type, ", ver: ", unsigned (response->ver));
          continue;
        }

      LogPrint (eLogDebug, "DHT: closestNodesLookup: Response from: ",
                response->from.substr (0, 15), "...");

      pbote::ResponsePacket packet;
      bool parsed = packet.from_comm_packet (*response, true);
      if (!parsed)
        {
          LogPrint (eLogWarning, "DHT: closestNodesLookup: Payload is too "
                                 "short, parsing skipped");
          continue;
        }

      if (packet.status != StatusCode::OK)
        {
          LogPrint (eLogWarning, "DHT: closestNodesLookup: Response status: ",
                    statusToString (packet.status), ", parsing skipped");
          continue;
        }

      if (packet.length == 0)
        {
          LogPrint (eLogWarning, "DHT: closestNodesLookup: Packet without "
                                 "payload, parsing skipped");
          continue;
        }

      size_t nodes_added = 0, nodes_dup = 0;
      std::vector<sp_node> node_list;

      if (unsigned (packet.data[1]) == 4)
        {
          pbote::PeerListPacketV4 peer_list;
          bool parsed = peer_list.fromBuffer (packet.data.data (),
                                              packet.length, true);

          if (!parsed)
          {
            LogPrint (eLogWarning,
                      "DHT: closestNodesLookup: V4 packet parsing failed");
            continue;
          }

          for (auto node : peer_list.data)
            {
              if (addNode (node))
                nodes_added++;
              else
                nodes_dup++;
              node_list.emplace_back (std::make_shared<Node> (node.ToBase64 ()));
            }
          LogPrint (eLogDebug, "DHT: closestNodesLookup: V4 nodes: ",
                    node_list.size (), ", added: ", nodes_added,
                    ", dup: ", nodes_dup);
        }

      if (unsigned (packet.data[1]) == 5)
        {
          pbote::PeerListPacketV5 peer_list;
          bool parsed = peer_list.fromBuffer (packet.data.data (),
                                              packet.length, true);

          if (!parsed)
          {
            LogPrint (eLogWarning,
                      "DHT: closestNodesLookup: V5 packet parsing failed");
            continue;
          }

          for (auto node : peer_list.data)
            {
              if (addNode (node))
                nodes_added++;
              else
                nodes_dup++;
              node_list.emplace_back (std::make_shared<Node> (node.ToBase64 ()));
            }
          LogPrint (eLogDebug, "DHT: closestNodesLookup: V5 nodes: ",
                    node_list.size (), ", added: ", nodes_added,
                    ", dup: ", nodes_dup);
        }

      if (node_list.empty ())
        {
          LogPrint (eLogDebug, "DHT: closestNodesLookup: node_list empty");
          continue;
        }

      LogPrint (eLogDebug, "DHT: closestNodesLookup: node_list size: ",
                node_list.size ());

      for (const auto &peer : node_list)
        {
          auto it = closestNodes.find (peer->GetIdentHash ());
          if (it == closestNodes.end ())
            {
              closestNodes.insert (
                  std::pair<HashKey, sp_node> (peer->GetIdentHash (), peer));
              LogPrint (eLogDebug, "DHT: closestNodesLookup: Added node: ",
                        peer->GetIdentHash ().ToBase64 ());
            }
        }
    }

  context.removeBatch (batch);

  /// If we have no responses - try with known nodes
  if (responses.empty ())
    {
      LogPrint (eLogWarning, "DHT: closestNodesLookup: Not enough "
                "responses, will use known nodes");
      return getClosestNodes (key, 20, false);
    }

  /// Now we can lock nodes
  calc_locks (responses);

  /// If the node is in the received list - the answering node has it unlocked
  /// If we have node locally and it's locked - unlock it
  size_t unlocked_counter = 0;
  auto node_itr = closestNodes.begin ();
  while (node_itr != closestNodes.end ())
    {
      auto known_node = findNode (node_itr->second->GetIdentHash ());
      if (known_node && known_node->locked ())
        {
          known_node->gotResponse ();
          unlocked_counter++;
        }
      ++node_itr;
    }

  LogPrint (eLogDebug, "DHT: closestNodesLookup: Unlocked node(s): ",
            unlocked_counter);

  for (const auto &node : closestNodes)
    addNode (node.second->ToBase64 ());

  return getClosestNodes (key, 20, false);
}

void
DHTworker::receiveRetrieveRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "DHT: receiveRetrieveRequest: Request from: ",
            packet->from.substr (0, 15), "...");

  if (packet->from == local_node_->ToBase64 ())
    {
      LogPrint (eLogWarning,
                "DHT: receiveRetrieveRequest: Self request, skipped");
      return;
    }

  if (addNode (packet->from))
    {
      LogPrint (eLogDebug,
                "DHT: receiveRetrieveRequest: Sender added to list");
    }

  pbote::ResponsePacket response;
  memcpy (response.cid, packet->cid, 32);

  pbote::RetrieveRequestPacket ret_packet;
  bool parsed = ret_packet.from_comm_packet (*packet);

  if (!parsed)
    {
      LogPrint (eLogDebug, "DHT: receiveRetrieveRequest: Can't parse packet");
      response.status = pbote::StatusCode::INVALID_PACKET;
      response.length = 0;

      PacketForQueue q_packet (packet->from, response.toByte ().data (),
                               response.toByte ().size ());
      context.send (q_packet);
      return;
    }

  HashKey hash (ret_packet.key);
  LogPrint (eLogDebug, "DHT: receiveRetrieveRequest: Request for type: ",
            ret_packet.data_type, ", key: ", hash.ToBase64 ());

  /// Try to find packet in storage
  std::vector<uint8_t> data;
  switch (ret_packet.data_type)
    {
    case ((uint8_t)'I'):
      data = dht_storage_.getIndex (hash);
      break;
    case ((uint8_t)'E'):
      data = dht_storage_.getEmail (hash);
      break;
    case ((uint8_t)'C'):
      data = dht_storage_.getContact (hash);
      break;
    default:
      break;
    }

  if (data.empty ())
    {
      LogPrint (eLogDebug, "DHT: receiveRetrieveRequest: Can't find type: ",
                ret_packet.data_type, ", key: ", hash.ToBase64 ());
      response.status = pbote::StatusCode::NO_DATA_FOUND;
      response.length = 0;
    }
  else
    {
      LogPrint (eLogDebug, "DHT: receiveRetrieveRequest: Found data type: ",
                ret_packet.data_type, ", key: ", hash.ToBase64 ());

      response.status = pbote::StatusCode::OK;
      response.length = data.size ();
      response.data = data;
    }

  PacketForQueue q_packet (packet->from, response.toByte ().data (),
                           response.toByte ().size ());
  context.send (q_packet);
}

void
DHTworker::receiveDeletionQuery (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "DHT: receiveDeletionQuery: request from: ",
            packet->from.substr (0, 15), "...");

  if (packet->from == local_node_->ToBase64 ())
    {
      LogPrint (eLogWarning,
                "DHT: receiveDeletionQuery: Self request, skipped");
      return;
    }

  if (addNode (packet->from))
    LogPrint (eLogDebug, "DHT: receiveDeletionQuery: Sender added to list");

  pbote::ResponsePacket response;
  memcpy (response.cid, packet->cid, 32);
  response.length = 0;

  pbote::DeletionQueryPacket del_query;

  bool parsed = del_query.from_comm_packet (*packet);
  if (!parsed)
    {
      LogPrint (eLogDebug, "DHT: receiveDeletionQuery: Packet is too short");
      response.status = pbote::StatusCode::INVALID_PACKET;
      response.length = 0;

      PacketForQueue q_packet (packet->from, response.toByte ().data (),
                           response.toByte ().size ());
      context.send (q_packet);
      return;
    }

  HashKey t_key (del_query.dht_key);

  LogPrint (eLogDebug, "DHT: receiveDeletionQuery: got request for key: ",
            t_key.ToBase64 ());

  // ToDo: After email removing it must be stored as DeletionInforPacket
  // Needed for delivery checking

  //auto data = dht_storage_.get_del_info (key);
  //if (data.empty ())
  //  {
  //    LogPrint (eLogDebug, "DHT: receiveDeletionQuery: key not found: ",
  //              t_key.ToBase64 ());
  //    response.status = pbote::StatusCode::NO_DATA_FOUND;
  //    response.length = 0;
  //  }
  //else
  //  {
  //    LogPrint (eLogDebug, "DHT: receiveDeletionQuery: found key: ",
  //              t_key.ToBase64 ());

  //    pbote::DeletionInfoPacket del_packet;
  //    del_packet.fromBuffer (res_packet.data, true);

  //    int key_cmp = memcmp (packet.key, del_packet.data[0].key, 32);
  //    int da_cmp = memcmp (packet.DA, del_packet.data[0].DA, 32);
  //  }
  //}

  response.status = pbote::StatusCode::NO_DATA_FOUND;
  response.length = 0;

  PacketForQueue q_packet (packet->from, response.toByte ().data (),
                           response.toByte ().size ());
  context.send (q_packet);
}

void
DHTworker::receiveStoreRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "DHT: StoreRequest: request from: ",
            packet->from.substr (0, 15), "...");

  if (packet->from == local_node_->ToBase64 ())
    {
      LogPrint (eLogWarning, "DHT: StoreRequest: Self request, skipped");
      return;
    }

  if (addNode (packet->from))
    LogPrint (eLogDebug, "DHT: StoreRequest: Sender added to list");

  StoreRequestPacket store_packet;

  pbote::ResponsePacket response;
  memcpy (response.cid, packet->cid, 32);
  response.length = 0;

  bool parsed = store_packet.from_comm_packet (*packet, true);
  if (!parsed)
    {
      LogPrint (eLogWarning, "DHT: receiveStoreRequest: Can't parse");
      response.status = pbote::StatusCode::INVALID_PACKET;
    }

  if ((store_packet.data[0] == (uint8_t)'I' ||
       store_packet.data[0] == (uint8_t)'E' ||
       store_packet.data[0] == (uint8_t)'C') &&
      store_packet.data[1] >= 4 && parsed)
    {
      bool prev_status = true;

      if (dht_storage_.limit_reached (store_packet.data.size ()))
        {
          LogPrint (eLogWarning, "DHT: StoreRequest: Storage limit reached");
          response.status = pbote::StatusCode::NO_DISK_SPACE;
          prev_status = false;
        }

      // ToDo: Check if not enough HashCash provided
      // response.status = pbote::StatusCode::INSUFFICIENT_HASHCASH;

      // ToDo: Check HashCash
      // response.status = pbote::StatusCode::INVALID_HASHCASH;

      int save_status = 0;

      if (prev_status)
        save_status = dht_storage_.safe (store_packet.data);

      if (prev_status && save_status == STORE_SUCCESS)
        {
          LogPrint (eLogDebug, "DHT: StoreRequest: Packet saved");
          response.status = pbote::StatusCode::OK;
        }
      else if (prev_status)
        {
          if (save_status == STORE_FILE_EXIST)
            response.status = pbote::StatusCode::DUPLICATED_DATA;
          else
            response.status = pbote::StatusCode::GENERAL_ERROR;
          LogPrint (eLogWarning, "DHT: StoreRequest: Packet not saved, status: ",
                    statusToString (response.status));
        }
    }
  else
    {
      LogPrint (eLogWarning, "DHT: StoreRequest: Unsupported packet, type: ",
                store_packet.data[0], ", ver: ", unsigned (store_packet.data[1]));
      response.status = pbote::StatusCode::INVALID_PACKET;
    }

  LogPrint (eLogDebug, "DHT: StoreRequest: Send status: ",
            statusToString (response.status));
  PacketForQueue q_packet (packet->from, response.toByte ().data (),
                           response.toByte ().size ());
  context.send (q_packet);
}

void
DHTworker::receiveEmailPacketDeleteRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "DHT: EmailPacketDelete: request from: ",
            packet->from.substr (0, 15), "...");

  if (packet->from == local_node_->ToBase64 ())
    {
      LogPrint (eLogWarning, "DHT: EmailPacketDelete: Self request, skipped");
      return;
    }

  if (addNode (packet->from))
    LogPrint (eLogDebug, "DHT: EmailPacketDelete: Sender added to list");

  pbote::ResponsePacket response;
  memcpy (response.cid, packet->cid, 32);
  response.length = 0;

  pbote::EmailDeleteRequestPacket delete_packet;
  bool parsed = delete_packet.from_comm_packet (*packet);
  if (!parsed)
    {
      LogPrint (eLogDebug, "DHT: EmailPacketDelete: Can't parse Email Delete");
      response.status = pbote::StatusCode::INVALID_PACKET;
      PacketForQueue q_packet (packet->from, response.toByte ().data (),
                               response.toByte ().size ());
      context.send (q_packet);
      return;
    }

  HashKey t_key (delete_packet.key);
  LogPrint (eLogDebug, "DHT: EmailPacketDelete: Got request for key: ",
            t_key.ToBase64 ());

  auto email_packet_data = dht_storage_.getEmail (t_key);

  if (email_packet_data.empty ())
    {
      LogPrint (eLogDebug, "DHT: EmailPacketDelete: Key not found: ",
                t_key.ToBase64 ());
      response.status = pbote::StatusCode::NO_DATA_FOUND;
      PacketForQueue q_packet (packet->from, response.toByte ().data (),
                               response.toByte ().size ());
      context.send (q_packet);
      return;
    }

  LogPrint (eLogDebug, "DHT: EmailPacketDelete: Found: ", t_key.ToBase64 ());

  pbote::EmailEncryptedPacket email_packet;
  parsed = email_packet.fromBuffer (email_packet_data.data (),
                                    email_packet_data.size (), true);

  uint8_t delHash[32] = {0};
  SHA256 (delete_packet.DA, 32, delHash);

  HashKey da_h (delete_packet.DA),
          dh_h (delHash),
          dv_h (email_packet.delete_hash);
  LogPrint (eLogDebug, "DHT: EmailPacketDelete: DA: ", da_h.ToBase64 ());
  LogPrint (eLogDebug, "DHT: EmailPacketDelete: DH: ", dh_h.ToBase64 ());
  LogPrint (eLogDebug, "DHT: EmailPacketDelete: DV: ", dv_h.ToBase64 ());

  /// Compare hashes
  //if (memcmp (delHash, email_delete_hash.data (), 32) != 0)
  if (!email_packet.da_valid (delete_packet.key, delete_packet.DA))
    {
      LogPrint (eLogWarning, "DHT: EmailPacketDelete: DA hash mismatch");
      response.status = pbote::StatusCode::INVALID_PACKET;
      PacketForQueue q_packet (packet->from, response.toByte ().data (),
                               response.toByte ().size ());
      context.send (q_packet);
      return;
    }

  LogPrint (eLogDebug, "DHT: EmailPacketDelete: DA hash match");

  if (dht_storage_.deleteEmail (t_key))
    {
      LogPrint (eLogDebug, "DHT: EmailPacketDelete: Packet removed");

      pbote::DeletionInfoPacket deleted_packet;
      deleted_packet.count = 1; // only 1 email packet in request
      pbote::DeletionInfoPacket::item item;
      memcpy(item.key, delete_packet.key, 32);
      memcpy(item.DA, delete_packet.DA, 32);
      item.time = email_packet.stored_time;

      deleted_packet.data.push_back (item);

      response.data = deleted_packet.toByte ();
      response.status = pbote::StatusCode::OK;
    }
  else
    {
      LogPrint (eLogDebug, "DHT: EmailPacketDelete: Can't remove packet");
      response.status = pbote::StatusCode::GENERAL_ERROR;
    }

  PacketForQueue q_packet (packet->from, response.toByte ().data (),
                           response.toByte ().size ());
  context.send (q_packet);

  if (response.status == pbote::StatusCode::OK)
    {
      LogPrint (eLogDebug,
                "DHT: EmailPacketDelete: Re-send request to other nodes");
      deleteEmail(t_key, DataE, delete_packet);
    }
}

void
DHTworker::receiveIndexPacketDeleteRequest (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "DHT: IndexPacketDelete: Request from: ",
            packet->from.substr (0, 15), "...");

  if (packet->from == local_node_->ToBase64 ())
    {
      LogPrint (eLogWarning, "DHT: IndexPacketDelete: Self request, skipped");
      return;
    }

  if (addNode (packet->from))
    LogPrint (eLogDebug, "DHT: IndexPacketDelete: Sender added to list");

  pbote::ResponsePacket response;
  memcpy (response.cid, packet->cid, 32);
  response.length = 0;

  pbote::IndexDeleteRequestPacket delete_packet;
  bool parsed = delete_packet.from_comm_packet (*packet);
  if (!parsed)
    {
      LogPrint (eLogDebug, "DHT: IndexPacketDelete: Can't parse Index Delete");
      response.status = pbote::StatusCode::INVALID_PACKET;
      PacketForQueue q_packet (packet->from, response.toByte ().data (),
                               response.toByte ().size ());
      context.send (q_packet);
      return;
    }

  HashKey t_key (delete_packet.dht_key);
  LogPrint (eLogDebug, "DHT: IndexPacketDelete: Got request for key: ",
            t_key.ToBase64 ());
  auto data = dht_storage_.getIndex (t_key);
  if (data.empty ())
    {
      LogPrint (eLogDebug, "DHT: IndexPacketDelete: Key not found: ",
                t_key.ToBase64 ());
      response.status = pbote::StatusCode::NO_DATA_FOUND;
      PacketForQueue q_packet (packet->from, response.toByte ().data (),
                               response.toByte ().size ());
      context.send (q_packet);
      return;
    }

  LogPrint (eLogDebug, "DHT: IndexPacketDelete: Found ", t_key.ToBase64 ());

  pbote::IndexPacket index_packet;
  parsed = index_packet.fromBuffer (data, true);

  if (!parsed)
    {
      LogPrint (eLogDebug, "DHT: IndexPacketDelete: Unparsable local: ",
                t_key.ToBase64 ());
      response.status = pbote::StatusCode::GENERAL_ERROR;
      PacketForQueue q_packet (packet->from, response.toByte ().data (),
                               response.toByte ().size ());
      context.send (q_packet);
      return;
    }

  pbote::DeletionInfoPacket deleted_packet;

  bool erased = false;
  for (auto item : delete_packet.data)
    {
      int32_t result = index_packet.erase_entry (item.key, item.da);
      if (result > 0)
        {
          erased = true;

          pbote::DeletionInfoPacket::item i_item;

          memcpy(i_item.key, item.key, 32);
          memcpy(i_item.DA, item.da, 32);
          i_item.time = result;

          deleted_packet.data.push_back (i_item);
        }
    }

  deleted_packet.count = deleted_packet.data.size ();
  response.data = deleted_packet.toByte ();

  if (!erased)
    {
      LogPrint (eLogDebug, "DHT: IndexPacketDelete: No matching DA's");
      response.status = pbote::StatusCode::INVALID_PACKET;
      PacketForQueue q_packet (packet->from, response.toByte ().data (),
                               response.toByte ().size ());
      context.send (q_packet);
      return;
    }

  LogPrint (eLogDebug, "DHT: IndexPacketDelete: There are matching DA's");

  /// Delete "old" packet
  bool deleted = dht_storage_.deleteIndex (t_key);
  int saved = STORE_FILE_NOT_STORED;

  /// Write "new" packet, if not empty
  if (!index_packet.data.empty ())
    saved = dht_storage_.safe (index_packet.toByte ());

  /// Compare statuses and prepare response
  if (deleted && saved == STORE_SUCCESS)
    {
      /// The cleaned packet has been saved
      LogPrint (eLogDebug, "DHT: IndexPacketDelete: Packet replaced");
      response.status = pbote::StatusCode::OK;
    }
  else if (!deleted && saved == STORE_SUCCESS)
    {
      /// In this case, we do not have a local packet
      /// it looks like this will never happen
      LogPrint (eLogDebug, "DHT: IndexPacketDelete: New packet saved");
      response.status = pbote::StatusCode::OK;
    }
  else if (deleted && index_packet.data.empty ())
    {
      /// There are no more entries in the packet
      LogPrint (eLogDebug, "DHT: IndexPacketDelete: Delete empty packet");
      response.status = pbote::StatusCode::OK;
    }
  else
    {
      LogPrint (eLogError, "DHT: IndexPacketDelete: Can't save new packet");

      if (saved == STORE_FILE_EXIST)
        response.status = pbote::StatusCode::DUPLICATED_DATA;
      else
        response.status = pbote::StatusCode::GENERAL_ERROR;
    }

  PacketForQueue q_packet (packet->from, response.toByte ().data (),
                           response.toByte ().size ());
  context.send (q_packet);

  // ToDo: re-send to other nodes
  //if (response.status == pbote::StatusCode::OK)
  //  {
  //    deleteIndexEntry (t_key, email_dht_key, email_del_auth);
  //  }
}

void
DHTworker::receiveFindClosePeers (const sp_comm_pkt &packet)
{
  LogPrint (eLogDebug, "DHT: receiveFindClosePeers: Request from: ",
            packet->from.substr (0, 15), "...");

  if (packet->from == local_node_->ToBase64 ())
    {
      LogPrint (eLogWarning,
                "DHT: receiveFindClosePeers: Self request, skipped");
      return;
    }

  if (addNode (packet->from))
    {
      LogPrint (eLogDebug,
                "DHT: receiveFindClosePeers: Sender added to list");
    }

  pbote::ResponsePacket response;
  memcpy (response.cid, packet->cid, 32);

  uint8_t key[32];
  std::memcpy (&key, packet->payload.data (), 32);
  HashKey t_key (key);

  LogPrint (eLogDebug, "DHT: receiveFindClosePeers: Got request for key: ",
            t_key.ToBase64 ());

  // ToDo:
  //auto closest_nodes = getClosestNodes (t_key, KADEMLIA_CONSTANT_K, false);
  auto closest_nodes = getClosestNodes (t_key, 20, false);

  if (closest_nodes.empty ())
    {
      LogPrint (eLogDebug,
                "DHT: receiveFindClosePeers: Can't find closest nodes");

      response.status = pbote::StatusCode::GENERAL_ERROR;
      response.length = 0;

      PacketForQueue q_packet (packet->from, response.toByte ().data (),
                               response.toByte ().size ());
      context.send (q_packet);
      return;
    }

  LogPrint (eLogDebug, "DHT: receiveFindClosePeers: Got ",
            closest_nodes.size (), " node(s) closest to key: ",
            t_key.ToBase64 ());
  response.status = pbote::StatusCode::OK;

  if (packet->ver == 4)
    {
      LogPrint (eLogDebug, "DHT: receiveFindClosePeers: Prepare PeerList V4");
      pbote::PeerListPacketV4 peer_list;
      peer_list.count = closest_nodes.size ();

      for (const auto &node : closest_nodes)
        {
          i2p::data::IdentityEx identity;
          identity.FromBase64 (node->ToBase64 ());
          peer_list.data.push_back (identity);
        }

      response.data = peer_list.toByte ();
    }

  if (packet->ver == 5)
    {
      LogPrint (eLogDebug, "DHT: receiveFindClosePeers: Prepare PeerList V5");
      pbote::PeerListPacketV5 peer_list;
      peer_list.count = closest_nodes.size ();

      for (const auto &node : closest_nodes)
        {
          i2p::data::IdentityEx identity;
          identity.FromBase64 (node->ToBase64 ());
          peer_list.data.push_back (identity);
        }

      response.data = peer_list.toByte ();
    }

  response.length = response.data.size ();

  LogPrint (eLogDebug, "DHT: receiveFindClosePeers: Send response with ",
            closest_nodes.size (), " node(s)");
  PacketForQueue q_packet (packet->from, response.toByte ().data (),
                           response.toByte ().size ());
  context.send (q_packet);
}

void
DHTworker::run ()
{
  while (started_)
    {
      writeNodes ();
      dht_storage_.update ();
      std::this_thread::sleep_for (std::chrono::seconds (60));
    }
}

std::vector<std::string>
DHTworker::readNodes ()
{
  std::string nodes_file_path
      = pbote::fs::DataDirPath (DEFAULT_NODE_FILE_NAME);
  LogPrint (eLogInfo, "DHT: readNodes: Read nodes from ", nodes_file_path);
  std::ifstream nodes_file (nodes_file_path);

  if (!nodes_file.is_open ())
    {
      LogPrint (eLogError, "DHT: readNodes: Can't open file ",
                nodes_file_path);
      return {};
    }

  std::vector<std::string> nodes_list;

  for (std::string line; getline (nodes_file, line);)
    {
      if (!line.empty () && line[0] != ('\n') && line[0] != '#')
        nodes_list.push_back (line);
    }
  return nodes_list;
}

bool
DHTworker::loadNodes ()
{
  size_t counter = 0, dup = 0;
  std::vector<std::string> nodes_list = readNodes ();
  std::vector<sp_node> nodes;

  for (const auto &node_str : nodes_list)
    {
      auto node = std::make_shared<Node> (node_str);
      nodes.push_back (node);
    }

  if (!nodes.empty ())
    {

      for (const auto &node : nodes)
        {
          LogPrint (eLogDebug, "DHT: loadNodes: Node: ", node->short_name ());
          auto t_hash = node->GetIdentHash ();
          bool result
              = m_nodes_.insert (std::pair<HashKey, sp_node> (t_hash, node))
                    .second;

          if (result)
            counter++;
          else
            dup++;
        }
    }

  if (counter > 0)
    {
      LogPrint (eLogInfo, "DHT: loadNodes: Nodes loaded: ", counter,
                ", duplicated: ", dup);

      /// Now we need lock all loaded nodes for initial check in
      /// first running of closestNodesLookupTask
      for (auto node : m_nodes_)
        node.second->noResponse ();

      return true;
    }

  // Only if we have no nodes in storage
  LogPrint (eLogInfo, "DHT: loadNodes: Can't load nodes, try bootstrap");

  std::vector<std::string> bootstrap_addresses;
  pbote::config::GetOption ("bootstrap.address", bootstrap_addresses);

  if (!bootstrap_addresses.empty ())
    {
      for (auto &bootstrap_address : bootstrap_addresses)
        {
          if (addNode (bootstrap_address))
            {
              i2p::data::IdentityEx new_node;
              new_node.FromBase64 (bootstrap_address);
              LogPrint (eLogDebug, "DHT: loadNodes: Successfully add node: ",
                        new_node.GetIdentHash ().ToBase64 ());
            }
        }
      return true;
    }
  else
    return false;
}

void
DHTworker::writeNodes ()
{
  std::string nodes_file_path
      = pbote::fs::DataDirPath (DEFAULT_NODE_FILE_NAME);
  std::ofstream nodes_file (nodes_file_path);

  LogPrint (eLogInfo, "DHT: writeNodes: Save nodes to ", nodes_file_path);

  if (!nodes_file.is_open ())
    {
      LogPrint (eLogError, "DHT: writeNodes: Can't open file ",
                nodes_file_path);
      return;
    }

  nodes_file << "# Each line is one Base64-encoded I2P destination.\n";
  nodes_file << "# Do not edit this file while pbote is running as it will be "
                "overwritten.\n\n";
  std::unique_lock<std::mutex> l (m_nodes_mutex_);

  size_t saved = 0;
  for (const auto &node : m_nodes_)
    {
      nodes_file << node.second->ToBase64 ();
      nodes_file << "\n";
      saved++;
    }

  nodes_file.close ();
  LogPrint (eLogDebug, "DHT: writeNodes: ", saved, " node(s) saved to FS");
}

void
DHTworker::calc_locks (std::vector<sp_comm_pkt> responses)
{
  size_t counter = 0;
  for (const auto &node : m_nodes_)
    {
      /// If we found response later node will be unlocked
      node.second->noResponse ();
      for (auto response : responses)
        {
          if (response->from == node.second->ToBase64 ())
            {
              node.second->gotResponse ();
              LogPrint (eLogDebug, "DHT: calc_locks: Node unlocked: ",
                        node.second->short_name ());
              counter++;
            }
        }
    }
  LogPrint (eLogDebug, "DHT: calc_locks: Nodes unlocked: ", counter);
}

pbote::FindClosePeersRequestPacket
DHTworker::findClosePeersPacket (HashKey key)
{
  pbote::FindClosePeersRequestPacket packet;
  /// Java will be answer with v4, pboted - with v5
  packet.ver = 5;
  /// Don't reuse request packets because PacketBatch will not add
  /// the same one more than once
  context.random_cid (packet.cid, 32);
  memcpy (packet.key, key.data (), 32);

  return packet;
}

pbote::RetrieveRequestPacket
DHTworker::retrieveRequestPacket (uint8_t data_type, HashKey key)
{
  pbote::RetrieveRequestPacket packet;
  context.random_cid (packet.cid, 32);
  memcpy (packet.key, key.data (), 32);
  packet.data_type = data_type;
  return packet;
}

} // kademlia
} // pbote
