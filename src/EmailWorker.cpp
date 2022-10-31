/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <ctime>
#include <iterator>
#include <openssl/sha.h>
#include <utility>
#include <vector>

#include "BoteContext.h"
#include "DHTworker.h"
#include "EmailWorker.h"

namespace bote
{

EmailWorker email_worker;

EmailWorker::EmailWorker ()
  : m_main_started (false),
    m_worker_thread (nullptr),
    m_send_thread (nullptr),
    m_delivery_thread (nullptr),
    m_incomplete_thread (nullptr)
{
}

EmailWorker::~EmailWorker ()
{
  stop ();

  if (m_worker_thread)
    {
      m_worker_thread->join ();

      delete m_worker_thread;
      m_worker_thread = nullptr;
    }
}

void
EmailWorker::start ()
{
  if (m_main_started && m_worker_thread)
    return;

  if (context.get_identities_count () == 0)
    LogPrint (eLogError, "EmailWorker: Have no Bote identities for start");
  else
    {
      startSendEmailTask ();
      startIncompleteEmailTask ();
      startCheckEmailTasks ();
      start_check_delivery_task ();
    }

  m_main_started = true;
  m_worker_thread = new std::thread ([this] { run (); });
  LogPrint (eLogInfo, "EmailWorker: Started");
}

void
EmailWorker::stop ()
{
  if (!m_main_started)
    return;

  LogPrint (eLogInfo, "EmailWorker: Stopping");

  m_main_started = false;

  m_check_cv.notify_all ();

  stopSendEmailTask ();
  stopIncompleteEmailTask ();
  stopCheckEmailTasks ();
  stop_check_delivery_task ();

  LogPrint (eLogInfo, "EmailWorker: Stopped");
}

void
EmailWorker::startCheckEmailTasks ()
{
  if (!m_main_started || !context.get_identities_count ())
    return;

  auto email_identities = context.getEmailIdentities ();
  // ToDo: move to object?
  for (const auto &identity : email_identities)
    {
      if (check_thread_exist (identity->publicName))
        {
          if (m_check_threads[identity->publicName]->joinable ())
            continue;
        }

      auto new_thread = std::make_shared<std::thread> (
          [this, identity] { check_email_task (identity); });

      m_check_threads[identity->publicName] = std::move (new_thread);

      LogPrint (eLogInfo, "EmailWorker: Check task ", identity->publicName,
                " started");
    }
}

bool
EmailWorker::stopCheckEmailTasks ()
{
  LogPrint (eLogInfo, "EmailWorker: Stopping check tasks");

  while (!m_check_threads.empty ())
    {
      auto it = m_check_threads.begin ();

      LogPrint (eLogInfo, "EmailWorker: Stopping task for ", it->first);
      it->second->join ();
      m_check_threads.erase (it->first);
    }

  LogPrint (eLogInfo, "EmailWorker: Check tasks stopped");
  return true;
}

void
EmailWorker::startIncompleteEmailTask ()
{
  if (!m_main_started)
    return;

  LogPrint (eLogInfo, "EmailWorker: Starting incomplete task");
  m_incomplete_thread = new std::thread ([this] { incomplete_email_task (); });
}

bool
EmailWorker::stopIncompleteEmailTask ()
{
  LogPrint (eLogInfo, "EmailWorker: Stopping incomplete task");

  if (m_incomplete_thread && !m_main_started)
    {
      m_incomplete_thread->join ();

      delete m_incomplete_thread;
      m_incomplete_thread = nullptr;
    }

  LogPrint (eLogInfo, "EmailWorker: Incomplete task stopped");
  return true;
}

void
EmailWorker::startSendEmailTask ()
{
  if (!m_main_started || !context.get_identities_count ())
    return;

  LogPrint (eLogInfo, "EmailWorker: Starting send task");
  m_send_thread = new std::thread ([this] { send_email_task (); });
}

bool
EmailWorker::stopSendEmailTask ()
{
  LogPrint (eLogInfo, "EmailWorker: Stopping send task");

  if (m_send_thread && !m_main_started)
    {
      m_send_thread->join ();

      delete m_send_thread;
      m_send_thread = nullptr;
    }

  LogPrint (eLogInfo, "EmailWorker: Send task stopped");
  return true;
}

void
EmailWorker::start_check_delivery_task ()
{
  if (!m_main_started)
    return;

  LogPrint (eLogInfo, "EmailWorker: Starting delivery task");
  m_delivery_thread = new std::thread ([this] { check_delivery_task (); });
}

bool
EmailWorker::stop_check_delivery_task ()
{
  LogPrint (eLogInfo, "EmailWorker: Stopping delivery task");

  if (m_delivery_thread && !m_main_started)
    {
      m_delivery_thread->join ();

      delete m_delivery_thread;
      m_delivery_thread = nullptr;
    }

  LogPrint (eLogInfo, "EmailWorker: Delivery task stopped");
  return true;
}

void
EmailWorker::run ()
{
  while (m_main_started)
    {
      size_t id_count = context.get_identities_count ();

      if (id_count)
        {
          LogPrint (eLogInfo, "EmailWorker: Identities now: ", id_count);

          startCheckEmailTasks ();
          /*
          for (auto check_thread : m_check_threads)
          {
            if (!check_thread.second->joinable ())
              {
                LogPrint (eLogDebug, "EmailWorker: Try to start check tasks");
                startCheckEmailTasks ();
              }
          }
          */

          if (!m_send_thread)
            {
              LogPrint (eLogDebug, "EmailWorker: Try to start send task");
              startSendEmailTask ();
            }

          if (!m_delivery_thread)
            {
              LogPrint (eLogDebug, "EmailWorker: Try to start delivery task");
              start_check_delivery_task ();
            }

          if (!m_incomplete_thread)
            {
              LogPrint (eLogDebug, "EmailWorker: Try to start incomplete task");
              startIncompleteEmailTask ();
            }
        }
      else
        {
          LogPrint (eLogWarning, "EmailWorker: Have no identities for start");
          stopSendEmailTask ();
          stopCheckEmailTasks ();
        }

      std::this_thread::sleep_for (std::chrono::seconds (60));
    }
}

void
EmailWorker::check_email_task (const sp_id_full &email_identity)
{
  bool first_run = true;
  auto check_timeout = std::chrono::seconds (FIRST_RUN_WAITING);
  std::string id_name = email_identity->publicName;

  LogPrint (eLogDebug, "EmailWorker: Check: ", id_name, ": Started");

  while (m_main_started)
    {
      /* ToDo: read interval parameter from config */
      if (!first_run)
        check_timeout = std::chrono::seconds(CHECK_EMAIL_INTERVAL);
      first_run = false;

      {
        std::unique_lock<std::mutex> lk (m_check_mutex);
        auto rc = m_check_cv.wait_for (lk, check_timeout);
        if (rc == std::cv_status::no_timeout)
          LogPrint (eLogDebug, "EmailWorker: Check: ", id_name,
                    ": Got notification");
        if (rc == std::cv_status::timeout)
          LogPrint (eLogDebug, "EmailWorker: Check: ", id_name,
                    ": Waiting finished");
        lk.unlock ();
      }

      auto index_packets = retrieve_index (email_identity);

      if (!index_packets.empty ())
        {
          LogPrint (eLogDebug, "EmailWorker: Check: ", id_name,
                    ": Got ", index_packets.size (), " index packets from DHT");
        }
      else
        {
          LogPrint (eLogDebug, "EmailWorker: Check: ", id_name,
                    ": Can't find index packets in DHT");
        }

      auto local_index_data
          = DHT_worker.getIndex (email_identity->identity.GetIdentHash ());

      if (!local_index_data.empty ())
        {
          LogPrint (eLogDebug, "EmailWorker: Check: ", id_name,
                    ": Got index packet from local storage");

          /// from_net is true, because we save it as is
          IndexPacket local_index_pkt;
          bool parsed = local_index_pkt.fromBuffer (local_index_data, true);
          if (parsed && local_index_pkt.data.size () == local_index_pkt.nump)
            {
              index_packets.push_back (local_index_pkt);
            }
        }
      else
        {
          LogPrint (eLogDebug, "EmailWorker: Check: ", id_name,
                    ": Can't find index packet in local storage");
        }

      LogPrint (eLogDebug, "EmailWorker: Check: ", id_name,
                ": Index count: ", index_packets.size ());

      if (index_packets.empty ())
        {
          LogPrint (eLogDebug, "EmailWorker: Check: ", id_name,
                ": Have no index for processing");
          LogPrint (eLogInfo, "EmailWorker: Check: ", id_name,
                    ": Round complete");
          continue;
        }

      if (!m_main_started)
        {
          LogPrint (eLogWarning, "EmailWorker: Check: ", id_name,
                    ": Not started");
          continue;
        }

      auto enc_mail_packets = retrieve_email (index_packets);

      LogPrint (eLogDebug, "EmailWorker: Check: ", id_name,
                ": Mail count: ", enc_mail_packets.size ());

      if (enc_mail_packets.empty ())
        {
          LogPrint (eLogDebug, "EmailWorker: Check: ", id_name,
                    ": Have no mail for process");
          LogPrint (eLogInfo, "EmailWorker: Check: ", id_name,
                    ": Round complete");
          continue;
        }

      auto metas = process_emails (email_identity, enc_mail_packets);

      remove_from_dht (metas);

      LogPrint (eLogInfo, "EmailWorker: Check: ", id_name, ": Round complete");
    }

  LogPrint (eLogInfo, "EmailWorker: Check: ", id_name, ": Stopped");
}

void
EmailWorker::incomplete_email_task ()
{
  bool first_run = true;
  auto check_timeout = std::chrono::seconds (FIRST_RUN_WAITING);

  LogPrint (eLogInfo, "EmailWorker: Incomplete: Started");

  while (m_main_started)
    {
      /* ToDo: read interval parameter from config */
      if (!first_run)
        check_timeout = std::chrono::seconds(CHECK_EMAIL_INTERVAL);
      first_run = false;

      {
        std::unique_lock<std::mutex> lk (m_incomplete_mutex);
        auto rc = m_check_cv.wait_for (lk, check_timeout);
        if (rc == std::cv_status::no_timeout)
          LogPrint (eLogDebug, "EmailWorker: Incomplete: Got notification");
        if (rc == std::cv_status::timeout)
          LogPrint (eLogDebug, "EmailWorker: Incomplete: Waiting finished");
        lk.unlock ();
      }

      auto metas = get_incomplete ();

      if (metas.empty ())
        {
          LogPrint (eLogDebug, "EmailWorker: Incomplete: Empty");
          continue;
        }

      for (auto meta : metas)
        {
          /// Skip if have no all parts
          if (!meta.second->is_full ())
            {
              LogPrint (eLogDebug, "EmailWorker: Incomplete: Not full, skipped");
              continue;
            }

          // ToDo: Check if mail already received

          Email mail;
          mail.metadata (meta.second);
          bool restored = mail.restore ();
          if (!restored)
            {
              LogPrint (eLogWarning, "EmailWorker: Incomplete: Can't restore: ",
                        mail.metadata ()->filename ());
              continue;
            }
          else
            {
              LogPrint (eLogInfo, "EmailWorker: Incomplete: Restored: ",
                        mail.get_message_id ());
            }

          mail.metadata ()->received (context.ts_now ());
          meta.second->received (context.ts_now ());

          bool saved = mail.save ("inbox");
          if (!saved)
            {
              LogPrint (eLogWarning, "EmailWorker: Incomplete: Not saved: ",
                        mail.get_message_id ());
              mail.metadata ()->received (0);
              meta.second->received (0);
            }
          else
            {
              LogPrint (eLogInfo, "EmailWorker: Incomplete: Saved: ",
                        mail.get_message_id ());
            }
        }

      LogPrint (eLogInfo, "EmailWorker: Incomplete: Round complete");
    }

  LogPrint (eLogInfo, "EmailWorker: Incomplete: Stopped");
}

void
EmailWorker::send_email_task ()
{
  bool first_run = true;
  auto check_timeout = std::chrono::seconds (FIRST_RUN_WAITING);
  v_sp_email outbox;

  LogPrint (eLogDebug, "EmailWorker: Send: Started");

  while (m_main_started)
    {
      /* ToDo: read interval parameter from config */
      if (!first_run)
        check_timeout = std::chrono::seconds(CHECK_EMAIL_INTERVAL);
      first_run = false;

      {
        std::unique_lock<std::mutex> lk (m_send_mutex);
        auto rc = m_check_cv.wait_for (lk, check_timeout);
        if (rc == std::cv_status::no_timeout)
          LogPrint (eLogDebug, "EmailWorker: Send: Got notification");
        if (rc == std::cv_status::timeout)
          LogPrint (eLogDebug, "EmailWorker: Send: Waiting finished");
        lk.unlock ();
      }

      std::vector<std::string> nodes;
      check_outbox (outbox);

      if (outbox.empty ())
        {
          LogPrint (eLogInfo, "EmailWorker: Send: Outbox empty");
          continue;
        }

      /// Store Encrypted Email Packet
      for (const auto &email : outbox)
        {
          auto storable_parts = email->get_storable ();
          for (auto storable_part : storable_parts)
            {
              if (email->skip ())
                {
                  LogPrint (eLogWarning, "EmailWorker: Send: Email skipped");
                  continue;
                }

              /// Send Store Request with Encrypted Email Packet to nodes
              nodes = DHT_worker.store (storable_part.first,
                                        DataE,
                                        storable_part.second);

              /// If have no OK store responses - mark message as skipped
              if (nodes.empty ())
                {
                  email->skip (true);
                  LogPrint (eLogWarning, "EmailWorker: Send: Email not sent");
                  continue;
                }

              LogPrint (eLogDebug, "EmailWorker: Send: Email sent to ",
                        nodes.size (), " node(s)");
            }
        }

      /// Store Index Packet
      for (const auto &email : outbox)
        {
          if (email->skip ())
            {
              LogPrint (eLogWarning, "EmailWorker: Send: Email skipped");
              continue;
            }

          /// Send Store Request with Index Packet to nodes
          nodes = DHT_worker.store (email->get_recipient ()->GetIdentHash (),
                                    DataI,
                                    email->get_storable_index ());

          /// If have no OK store responses - mark message as skipped
          if (nodes.empty ())
            {
              email->skip (true);
              LogPrint (eLogWarning, "EmailWorker: Send: Index not sent");
              continue;
            }

          DHT_worker.safe (email->get_index ().toByte ());
          LogPrint (eLogDebug, "EmailWorker: Send: Index send to ",
                    nodes.size (), " node(s)");

          auto enc_parts = email->encrypted ();
          for (auto enc_part : enc_parts)
            DHT_worker.safe (enc_part->toByte ());
        }

      auto email_it = outbox.begin ();
      while (email_it != outbox.end ())
        {
          if ((*email_it)->skip ())
            {
              ++email_it;
              continue;
            }

          (*email_it)->get_metadata ()->deleted (false);
          (*email_it)->save ();
          (*email_it)->move ("sent");
          email_it = outbox.erase(email_it);
          LogPrint (eLogInfo, "EmailWorker: Send: Email sent, moved to sent");
        }

      LogPrint (eLogInfo, "EmailWorker: Send: Round complete");
    }

  LogPrint (eLogInfo, "EmailWorker: Send: Stopped");
}

void
EmailWorker::check_delivery_task ()
{
  bool first_run = true;
  auto check_timeout = std::chrono::seconds (FIRST_RUN_WAITING);
  v_sp_email_meta sentbox;
  std::vector<std::shared_ptr<DeletionInfoPacket> > results;

  LogPrint (eLogInfo, "EmailWorker: Delivery: Started");

  while (m_main_started)
    {
      /* ToDo: read interval parameter from config */
      if (!first_run)
        check_timeout = std::chrono::seconds(DELIVERY_EMAIL_INTERVAL);
      first_run = false;

      {
        std::unique_lock<std::mutex> lk (m_delivery_mutex);
        auto rc = m_check_cv.wait_for (lk, check_timeout);
        if (rc == std::cv_status::no_timeout)
          LogPrint (eLogDebug, "EmailWorker: Delivery: Got notification");
        if (rc == std::cv_status::timeout)
          LogPrint (eLogDebug, "EmailWorker: Delivery: Waiting finished");
        lk.unlock ();
      }

      check_sentbox (sentbox);

      if (sentbox.empty ())
        {
          LogPrint (eLogInfo, "EmailWorker: Delivery: Sentbox empty");
          continue;
        }

      for (auto meta : sentbox)
        {
          if (meta->delivered ())
            {
              LogPrint (eLogInfo, "EmailWorker: Delivery: Mail ",
                        meta->message_id (), " is already delivered");
              continue;
            }

          size_t new_valid = 0;
          auto mail_parts = meta->get_parts ();

          for (auto mail_part : (*mail_parts))
            {
              if (mail_part.second.delivered || mail_part.second.deleted)
                {
                  LogPrint (eLogDebug, "EmailWorker: Delivery: part ",
                            mail_part.second.key.ToBase64 (),
                            " is already delivered");
                  continue;
                }

              // Make DeletionQuery to DHT
              results = DHT_worker.deletion_query (mail_part.second.key);

              // Compare DeletionInfoPacket in results with Email meta (key, DA)
              for (auto del_info : results)
                {
                  size_t new_filled = meta->fill (del_info);
                  new_valid += new_filled;
                }
            }

          for (auto part : (*mail_parts))
            {
              LogPrint (eLogDebug, "EmailWorker: Delivery: part: ",
                        part.second.key.ToBase64 (),", delivered: ",
                        part.second.delivered ? "true" : "false");
            }

          if (meta->delivered ())
            {
              LogPrint (eLogInfo, "EmailWorker: Delivery: Mail ",
                        meta->message_id (), " is delivered");
              meta->received (context.ts_now ());
              meta->save ();
              continue;
            }

          if (new_valid > 0)
            {
              meta->save ();
              LogPrint (eLogInfo, "EmailWorker: Delivery: Got ", new_valid,
                        " new deletion info for message ",
                        meta->message_id ());
            }
        }

      LogPrint (eLogInfo, "EmailWorker: Delivery: Round complete");
    }

  LogPrint (eLogInfo, "EmailWorker: Delivery: Stopped");
}

v_index
EmailWorker::retrieve_index (const sp_id_full &identity)
{
  auto identity_hash = identity->identity.GetIdentHash ();
  LogPrint (eLogDebug, "EmailWorker: retrieve_index: Try to find index for: ",
            identity_hash.ToBase64 ());

  /* Use findAll rather than findOne because some peers might have an
   *  incomplete set of Email Packet keys, and because we want to send
   *  IndexPacketDeleteRequests to all of them.
   */
  auto results = DHT_worker.findAll (identity_hash, DataI);
  if (results.empty ())
    {
      LogPrint (eLogWarning,
                "EmailWorker: retrieve_index: Can't find index for: ",
                identity_hash.ToBase64 ());
      return {};
    }

  std::map<i2p::data::Tag<32>, IndexPacket> indices;
  /// Retrieve index packets
  for (const auto &response : results)
    {
      if (response->type != type::CommN)
        {
          // ToDo: looks like in case if we got request to ourself, for now we
          // just skip it
          LogPrint (eLogWarning, "EmailWorker: retrieve_index: Got ",
                    "non-response packet in batch, type: ", response->type,
                    ", ver: ", unsigned (response->ver));
          continue;
        }

      LogPrint (eLogDebug, "EmailWorker: retrieve_index: Got response from: ",
                response->from.substr (0, 15), "...");
      
      ResponsePacket res_packet;
      bool parsed = res_packet.from_comm_packet (*response, true);

      if (!parsed)
        {
          LogPrint (eLogDebug, "EmailWorker: retrieve_index: ",
                    "Can't parse packet, skipped");
          continue;
        }

      if (res_packet.status != StatusCode::OK)
        {
          LogPrint (eLogWarning, "EmailWorker: retrieve_index: Status: ",
                    statusToString (res_packet.status));
          continue;
        }

      if (res_packet.length < 38)
        {
          LogPrint (eLogDebug, "EmailWorker: retrieve_index: ",
                    "Empty packet, skipped");
          continue;
        }

      if (DHT_worker.safe (res_packet.data))
        LogPrint (eLogDebug, "EmailWorker: retrieve_index: Index packet saved");

      IndexPacket index_packet;
      parsed = index_packet.fromBuffer (res_packet.data, true);

      if (!parsed)
        {
          LogPrint (eLogDebug, "EmailWorker: retrieve_index: ",
                    "Can't parse packet, skipped");
          continue;
        }

      if (index_packet.data.empty ())
        {
          LogPrint (eLogWarning, "EmailWorker: retrieve_index: Empty packet");
          continue;
        }

      // ToDo: save index packets for interrupt case

      i2p::data::Tag<32> hash (index_packet.hash);
      indices.insert (std::pair<i2p::data::Tag<32>, IndexPacket> (hash, index_packet));
    }

  LogPrint (eLogDebug, "EmailWorker: retrieve_index: Indices parsed: ",
            indices.size ());

  v_index res;
  res.reserve (indices.size ());

  for (const auto &packet : indices)
    res.push_back (packet.second);

  return res;
}

v_enc_email
EmailWorker::retrieve_email (const v_index &indices)
{
  std::vector<std::shared_ptr<CommunicationPacket> > responses;
  v_enc_email local_email_packets;

  for (const auto &index : indices)
    {
      for (auto entry : index.data)
        {
          i2p::data::Tag<32> hash (entry.key);

          auto email_packet_data = DHT_worker.getEmail (hash);
          if (!email_packet_data.empty ())
            {
              LogPrint (eLogDebug,
                        "EmailWorker: retrieve_email: Got local "
                        "encrypted email for key: ", hash.ToBase64 ());
              EmailEncryptedPacket email_packet;
              bool parsed = email_packet.fromBuffer (
                  email_packet_data.data (), email_packet_data.size (),
                  true);

              if (parsed)
                {
                  local_email_packets.push_back (email_packet);
                  continue;
                }

              LogPrint (eLogDebug, "EmailWorker: retrieve_email: ",
                            "Can't parse local packet ", hash.ToBase64 ());
              // ToDo: remove malformed packet?
            }

          LogPrint (eLogDebug, "EmailWorker: retrieve_email: Can't find packet"
                    " for key: ", hash.ToBase64 (), " localy, try to ask DHT");

          auto dht_results = DHT_worker.findAll (hash, DataE);

          LogPrint (eLogDebug, "EmailWorker: retrieve_email: Got ",
                    dht_results.size (), " DHT results for key ",
                    hash.ToBase64 ());

          responses.insert (responses.end (), dht_results.begin (),
                            dht_results.end ());
        }
    }

  LogPrint (eLogDebug, "EmailWorker: retrieve_email: Got ",
            local_email_packets.size (), " local and ", responses.size (),
            " DHT results");

  std::map<i2p::data::Tag<32>, EmailEncryptedPacket> mail_packets;
  for (const auto &response : responses)
    {
      if (response->type != type::CommN)
        {
          // ToDo: looks like we got request to ourself, for now just skip it
          LogPrint (eLogWarning,
                    "EmailWorker: retrieve_email: Got non-response packet in "
                    "batch, type: ", response->type, ", ver: ",
                    unsigned (response->ver));
          continue;
        }

      ResponsePacket res_packet;
      bool parsed = res_packet.from_comm_packet (*response, true);

      if (!parsed)
        {
          LogPrint (eLogDebug, "EmailWorker: retrieve_email: ",
                    "Can't parse packet, skipped");
          continue;
        }

      if (res_packet.status != StatusCode::OK)
        {
          LogPrint (eLogWarning, "EmailWorker: retrieve_email: Status: ",
                    statusToString (res_packet.status));
          continue;
        }

      if (res_packet.length <= 0)
        {
          LogPrint (eLogDebug, "EmailWorker: retrieve_email: ",
                    "Empty packet, skipped");
          continue;
        }

      LogPrint (eLogDebug, "EmailWorker: retrieve_email: Got email ",
                "packet, payload size: ", res_packet.length);

      if (DHT_worker.safe (res_packet.data))
        LogPrint (eLogDebug, "EmailWorker: retrieve_email: Encrypted ",
                  "email packet saved locally");

      EmailEncryptedPacket email_packet;
      parsed = email_packet.fromBuffer (res_packet.data.data (),
                                        res_packet.length, true);

      if (!parsed || email_packet.edata.empty ())
        {
          LogPrint (eLogWarning, "EmailWorker: retrieve_email: Mail packet",
                    " without entries");
          continue;
        }

      i2p::data::Tag<32> hash (email_packet.key);
      mail_packets.insert (std::pair<i2p::data::Tag<32>, 
                                     EmailEncryptedPacket> (hash, email_packet));
    }

  LogPrint (eLogDebug, "EmailWorker: retrieve_email: Parsed mail packets: ",
            mail_packets.size ());

  for (auto local_packet : local_email_packets)
    {
      i2p::data::Tag<32> hash (local_packet.key);
      mail_packets.insert (std::pair<i2p::data::Tag<32>,
                                     EmailEncryptedPacket> (hash, local_packet));
    }

  LogPrint (eLogDebug, "EmailWorker: retrieve_email: Mail packets: ",
            mail_packets.size ());

  v_enc_email res;
  res.reserve (mail_packets.size ());

  for (const auto &packet : mail_packets)
    res.push_back (packet.second);

  return res;
}

void
EmailWorker::check_outbox (v_sp_email &emails)
{
  LogPrint (eLogDebug, "EmailWorker: check_outbox: Updating");
  /// outbox contain plain text packets
  // ToDo: encrypt all local stored emails with master password
  std::string outboxPath = bote::fs::DataDirPath ("outbox");
  std::vector<std::string> mails_path;
  auto result = bote::fs::ReadDir (outboxPath, mails_path);

  if (!result)
    {
      LogPrint (eLogDebug, "EmailWorker: check_outbox: No emails for sending");
      return;
    }

  auto path_itr = mails_path.begin ();
  while (path_itr != mails_path.end ())
    {
      if ((*path_itr).compare ((*path_itr).size()-5, 5, META_FILE_EXTENSION) == 0)
        {
          LogPrint (eLogDebug, "EmailWorker: check_outbox: Skipping metadata: ",
                    (*path_itr));
          path_itr = mails_path.erase (path_itr);
          continue;
        }
      ++path_itr;
    }

  for (const auto &mail : emails)
    {
      /// If we check outbox - we can try to re-send skipped emails
      mail->skip (false);

      auto path = std::find(mails_path.begin (),
                            mails_path.end (),
                            mail->filename ());
      if (path != std::end(mails_path))
        {
          LogPrint (eLogDebug, "EmailWorker: check_outbox: Already in outbox: ",
                    mail->filename ());
          mails_path.erase (path);
        }
    }

  for (const auto &mail_path : mails_path)
    {

      /// Read mime packet
      std::ifstream file (mail_path, std::ios::binary);
      std::vector<uint8_t> bytes ((std::istreambuf_iterator<char> (file)),
                                  (std::istreambuf_iterator<char> ()));
      file.close ();

      Email mailPacket;
      mailPacket.fromMIME (bytes);

      if (mailPacket.length () > 0)
        LogPrint (eLogDebug,"EmailWorker: check_outbox: loaded: ", mail_path);
      else
        {
          LogPrint (eLogWarning, "EmailWorker: check_outbox: can't read: ",
                    mail_path);
          continue;
        }

      mailPacket.filename (mail_path);

      /**
       * Check if FROM and TO fields have valid public names, else
       * Check if <name@domain> in AddressBook for replacement
       * if not found - log warning and skip
       * if replaced - save modified email to file to keep changes
       */
      std::string from_label = mailPacket.get_from_label ();
      std::string from_address = mailPacket.get_from_address ();
      std::string to_label = mailPacket.get_to_label();
      std::string to_address = mailPacket.get_to_addresses();

      LogPrint (eLogDebug,"EmailWorker: check_outbox: from: ", from_label);
      LogPrint (eLogDebug,"EmailWorker: check_outbox: from: ", from_address);
      LogPrint (eLogDebug,"EmailWorker: check_outbox: to: ", to_label);
      LogPrint (eLogDebug,"EmailWorker: check_outbox: to: ", to_address);

      /// First try to find our identity
      // ToDo: Anon send
      if (from_label.empty () || from_address.empty ())
        {
          LogPrint (eLogWarning, "EmailWorker: check_outbox: FROM empty");
          continue;
        }

      auto label_from_identity = context.identityByName (from_label);
      auto address_from_identity = context.identityByName (from_address);

      if (label_from_identity)
        mailPacket.set_sender_identity(label_from_identity);
      else if (address_from_identity)
        mailPacket.set_sender_identity(address_from_identity);
      else
        {
          LogPrint (eLogError, "EmailWorker: check_outbox: Unknown, label: ",
                    from_label, ", address: ", from_address);
          mailPacket.set_sender_identity(nullptr);
          continue;
        }

      // Now we can try to set correct TO field
      if (to_label.empty () || to_address.empty ())
        {
          LogPrint (eLogWarning, "EmailWorker: check_outbox: TO empty");
          continue;
        }

      std::string old_to_address = mailPacket.field("To");

      auto label_to_address = context.address_for_name (to_label);
      auto address_to_address = context.address_for_alias (to_address);

      std::string new_to, b_dest;

      if (!label_to_address.empty ())
        {
          new_to.append (to_label + " <" + label_to_address + ">");
          b_dest = label_to_address;
        }
      else if (!address_to_address.empty ())
        {
          new_to.append (to_label + " <" + address_to_address + ">");
          b_dest = address_to_address;
        }
      else
        {
          LogPrint (eLogWarning, "EmailWorker: check_outbox: Can't find ",
                    to_address, ", try to use as is");
          to_address = mailPacket.get_to_mailbox ();
          new_to.append (to_label + " <" + to_address + ">");
          b_dest = to_address;
        }

      LogPrint (eLogDebug,"EmailWorker: check_outbox: TO replaced, old: ",
                old_to_address, ", new: ", new_to);

      mailPacket.set_to (new_to);
      mailPacket.set_recipient_identity(b_dest);

      if (mailPacket.skip ())
        {
          LogPrint (eLogDebug,"EmailWorker: check_outbox: Email skipped");
          continue;
        }

      //mailPacket.sign (); //ToDo

      auto recipient = mailPacket.get_recipient ();

      if (!recipient)
        {
          LogPrint (eLogError,"EmailWorker: check_outbox: Recipient error");
          continue;
        }

      if (recipient->GetKeyType () == KEY_TYPE_X25519_ED25519_SHA512_AES256CBC)
        mailPacket.compress (Email::CompressionAlgorithm::ZLIB);
      else
        mailPacket.compress (Email::CompressionAlgorithm::UNCOMPRESSED);

      /// On this step will be generated Message-ID and
      ///   it will be saved and not be re-generated
      ///   on the next loading (if first attempt failed)
      //mailPacket.compose ();
      mailPacket.split ();
      mailPacket.encrypt ();
      mailPacket.save ();
      mailPacket.fill_storable ();

      if (!mailPacket.empty ())
        emails.push_back (std::make_shared<Email> (mailPacket));
    }

  LogPrint (eLogInfo, "EmailWorker: check_outbox: Got ", emails.size (),
            " email(s)");
}

void
EmailWorker::check_sentbox (v_sp_email_meta &metas)
{
  LogPrint (eLogDebug, "EmailWorker: check_sentbox: Updating");
  /// sent contain plain MIME's
  // ToDo: encrypt with master password
  std::string sentbox_path = bote::fs::DataDirPath ("sent");
  std::vector<std::string> metas_path;
  auto result = bote::fs::ReadDir (sentbox_path, metas_path);

  if (!result)
    {
      LogPrint (eLogDebug, "EmailWorker: check_sentbox: Empty");
      return;
    }

  auto path_itr = metas_path.begin ();
  while (path_itr != metas_path.end ())
    {
      if ((*path_itr).compare ((*path_itr).size()-5, 5, META_FILE_EXTENSION) == 0)
        {
          LogPrint (eLogDebug, "EmailWorker: check_sentbox: valid: ",
                    (*path_itr));
          ++path_itr;
          continue;
        }
      else
        path_itr = metas_path.erase (path_itr);
    }

  for (const auto &meta : metas)
    {
      auto path = std::find(metas_path.begin (), metas_path.end (),
                            meta->filename ());
      if (path != metas_path.end ())
        {
          LogPrint (eLogDebug, "EmailWorker: check_sentbox: Already loaded: ",
                    meta->filename ());
          metas_path.erase (path);
        }
    }

  for (const auto &meta_path : metas_path)
    {
      EmailMetadata metadata;
      auto loaded = metadata.load (meta_path);

      if (loaded)
        metas.push_back (std::make_shared<EmailMetadata> (metadata));
      else
        LogPrint (eLogWarning, "EmailWorker: check_sentbox: Can't load: ",
                  meta_path);
    }

  LogPrint (eLogInfo, "EmailWorker: check_sentbox: Got ", metas.size (),
            " email(s)");
}

map_sp_email_meta
EmailWorker::get_incomplete ()
{
  LogPrint (eLogDebug, "EmailWorker: get_incomplete: Updating");
  /// incomplete contain plain text packets
  // ToDo: encrypt all local stored emails with master password
  std::string incomplete_path = bote::fs::DataDirPath ("incomplete");
  std::vector<std::string> packets_path;
  auto result = bote::fs::ReadDir (incomplete_path, packets_path);

  if (!result)
    {
      LogPrint (eLogDebug, "EmailWorker: get_incomplete: No meta for checking");
      return {};
    }

  map_sp_email_meta metas;

  for (const auto &packet_path : packets_path)
    {
      std::ifstream file (packet_path, std::ios::binary);
      std::vector<uint8_t> bytes ((std::istreambuf_iterator<char> (file)),
                                  (std::istreambuf_iterator<char> ()));
      file.close ();

      if (bytes.empty ())
        {
          LogPrint (eLogWarning, "EmailWorker: get_incomplete: Can't load: ",
                    packet_path);
          continue;
        }

      EmailUnencryptedPacket packet;
      bool parsed = packet.fromBuffer (bytes, true);

      if (!parsed)
        {
          LogPrint (eLogDebug, "EmailWorker: get_incomplete: Can't parse");
          continue;
        }

      i2p::data::Tag<32> packet_dht_key;
      std::string dht_base
        = bote::remove_extension (bote::base_name (packet_path));
      packet_dht_key.FromBase64 (dht_base);

      if (memcmp(packet.mes_id, zero_array, 32) == 0)
        {
          LogPrint (eLogWarning, "EmailWorker: get_incomplete: Message-ID is empty");

          bote::fs::Remove (packet_path);

          LogPrint (eLogInfo, "EmailWorker: get_incomplete: ",
                    "Malformed packet removed: ", packet_path);

          continue;
        }

      std::shared_ptr<EmailMetadata> metadata;

      i2p::data::Tag<32> mid_key (packet.mes_id);

      LogPrint (eLogDebug, "EmailWorker: get_incomplete: Message-ID: ",
                mid_key.ToBase64 ());

      auto meta_itr = metas.find(mid_key);
      if (meta_itr != metas.end())
        {
          LogPrint (eLogDebug, "EmailWorker: get_incomplete: Found packet for message ",
                    mid_key.ToBase64 ());
          metadata = (*meta_itr).second;
        }
      else
        {
          LogPrint (eLogDebug, "EmailWorker: get_incomplete: New Message-ID: ",
                    mid_key.ToBase64 ());

          metadata = std::make_shared<EmailMetadata>();

          std::vector<uint8_t> mid_vec(std::begin(packet.mes_id),
                                       std::end(packet.mes_id));

          metadata->message_id_bytes (mid_vec);
          metadata->fr_count (packet.fr_count);
          //metadata->dht();

          metas.insert (std::pair<i2p::data::Tag<32>,
                        std::shared_ptr<EmailMetadata>> (mid_key, metadata));
        }

      auto parts = metadata->get_parts ();
      EmailMetadata::Part metadata_part;

      auto meta_part_itr = parts->find(packet.fr_id);
      if (meta_part_itr == parts->end())
        {
          LogPrint (eLogDebug, "EmailWorker: get_incomplete: New part, id: ",
                    packet.fr_id);
          metadata_part.id = packet.fr_id;
          metadata_part.key = packet_dht_key;
          metadata_part.DA = i2p::data::Tag<32>(packet.DA);

          metadata->add_part (metadata_part);
        }
      else
        {
          LogPrint (eLogDebug, "EmailWorker: get_incomplete: Metadata for part ",
                    packet.fr_id, " already exist");
        }

      auto parts_meta = metadata->get_parts ();
      LogPrint (eLogDebug, "EmailWorker: get_incomplete: Metadata id: ",
                    metadata->message_id (), ", parts: ", parts_meta->size ());
      for (auto m_part : (*parts_meta))
        {
          LogPrint (eLogDebug, "EmailWorker: get_incomplete: part id: ",
                    m_part.first, ", #", m_part.second.id, ", key: ",
                    m_part.second.key.ToBase64 ());
        }
    }

  LogPrint (eLogInfo, "EmailWorker: get_incomplete: Got ", metas.size (),
            " packet(s)");
  return metas;
}

v_sp_email
EmailWorker::check_inbox ()
{
  LogPrint (eLogDebug, "EmailWorker: check_inbox: Updating");
  // ToDo: encrypt all local stored emails
  std::string outboxPath = bote::fs::DataDirPath ("inbox");
  std::vector<std::string> mails_path;
  auto result = bote::fs::ReadDir (outboxPath, mails_path);

  v_sp_email emails;

  if (result)
    {
      for (const auto &mail_path : mails_path)
        {
          /// Read mime packet
          std::ifstream file (mail_path, std::ios::binary);
          std::vector<uint8_t> bytes ((std::istreambuf_iterator<char> (file)),
                                      (std::istreambuf_iterator<char> ()));
          file.close ();

          Email mailPacket;
          mailPacket.fromMIME (bytes);

          if (mailPacket.length () > 0)
            {
              LogPrint (eLogDebug, "EmailWorker: check_inbox: File loaded: ",
                        mail_path);
            }
          else
            {
              LogPrint (eLogWarning,
                        "EmailWorker: check_inbox: Can't read file: ",
                        mail_path);
              continue;
            }

          // ToDo: check signature and set header field

          mailPacket.compose ();
          mailPacket.filename (mail_path);

          if (!mailPacket.empty ())
            emails.push_back (std::make_shared<Email> (mailPacket));
        }
    }

  LogPrint (eLogDebug, "EmailWorker: check_inbox: Found ", emails.size (),
            " email(s).");

  return emails;
}

map_sp_email_meta
EmailWorker::process_emails (const sp_id_full &identity,
                           const v_enc_email &mail_packets)
{
  LogPrint (eLogDebug, "EmailWorker: process_emails: Emails for process: ",
            mail_packets.size ());

  size_t counter = 0;
  map_sp_email_meta metas;

  for (auto enc_mail : mail_packets)
    {
      std::vector<uint8_t> unencrypted_email_data;

      if (enc_mail.edata.empty ())
        {
          LogPrint (eLogWarning, "EmailWorker: process_emails: Packet is empty ");
          continue;
        }

      unencrypted_email_data = identity->identity.Decrypt (
          enc_mail.edata.data (), enc_mail.edata.size ());

      if (unencrypted_email_data.empty ())
        {
          LogPrint (eLogWarning, "EmailWorker: process_emails: Can't decrypt");
          continue;
        }

      bote::EmailUnencryptedPacket plain_packet;

      bool parsed = plain_packet.fromBuffer (unencrypted_email_data, true);
      if (!parsed)
        {
          LogPrint (eLogWarning, "EmailWorker: process_emails: Can't parse");
          continue;
        }

      if (!plain_packet.check (enc_mail.delete_hash))
        {
          i2p::data::Tag<32> cur_hash (enc_mail.delete_hash);
          LogPrint (eLogWarning, "EmailWorker: process_emails: email ",
                    cur_hash.ToBase64 (), " is unequal");
          continue;
        }

      i2p::data::Tag<32> dht_key (enc_mail.key);
      std::string pkt_path = bote::fs::DataDirPath ("incomplete",
                                                    dht_key.ToBase64 () + ".pkt");

      std::ofstream file (pkt_path, std::ofstream::binary | std::ofstream::out);

      if (!file.is_open ())
        {
          LogPrint(eLogError, "Email: process_emails: Can't open file ",
                   pkt_path);
          continue;
        }

      auto bytes = plain_packet.toByte ();

      file.write (reinterpret_cast<const char *> (bytes.data ()), bytes.size ());
      file.close ();

      // Filling meta here and return to Check task for sending remove requests
      std::shared_ptr<EmailMetadata> metadata;

      i2p::data::Tag<32> mid_key (plain_packet.mes_id);

      LogPrint (eLogDebug, "EmailWorker: process_emails: Message-ID: ",
                mid_key.ToBase64 ());

      auto meta_itr = metas.find(mid_key);
      if (meta_itr != metas.end())
        {
          LogPrint (eLogDebug, "EmailWorker: process_emails: Found packet for message ",
                    mid_key.ToBase64 ());
          metadata = (*meta_itr).second;
        }
      else
        {
          LogPrint (eLogDebug, "EmailWorker: process_emails: New Message-ID: ",
                    mid_key.ToBase64 ());

          metadata = std::make_shared<EmailMetadata>();

          std::vector<uint8_t> mid_vec(std::begin(plain_packet.mes_id),
                                       std::end(plain_packet.mes_id));

          metadata->message_id_bytes (mid_vec);
          metadata->fr_count (plain_packet.fr_count);
          metadata->dht(identity->identity.GetIdentHash ());

          metas.insert (std::pair<i2p::data::Tag<32>,
                        std::shared_ptr<EmailMetadata>> (mid_key, metadata));
        }

      auto parts = metadata->get_parts ();
      EmailMetadata::Part metadata_part;

      auto meta_part_itr = parts->find(plain_packet.fr_id);
      if (meta_part_itr == parts->end())
        {
          LogPrint (eLogDebug, "EmailWorker: process_emails: New part, id: ",
                    plain_packet.fr_id);
          metadata_part.id = plain_packet.fr_id;
          metadata_part.key = dht_key;
          metadata_part.DA = i2p::data::Tag<32>(plain_packet.DA);

          metadata->add_part (metadata_part);
        }
      else
        {
          LogPrint (eLogDebug, "EmailWorker: process_emails: Metadata for part ",
                    plain_packet.fr_id, " already exist");
        }

      auto parts_meta = metadata->get_parts ();
      LogPrint (eLogDebug, "EmailWorker: process_emails: Metadata id: ",
                    metadata->message_id (), ", parts: ", parts_meta->size ());
      for (auto m_part : (*parts_meta))
        {
          LogPrint (eLogDebug, "EmailWorker: process_emails: part id: ",
                    m_part.first, ", #", m_part.second.id, ", key: ",
                    m_part.second.key.ToBase64 ());
        }      

      counter++;
    }

  LogPrint (eLogDebug, "EmailWorker: process_emails: Emails processed: ", counter);

  return metas;
}

void
EmailWorker::remove_from_dht (map_sp_email_meta metas)
{
  LogPrint (eLogInfo, "EmailWorker: remove_from_dht: Started");
  for (auto meta : metas)
    {
      auto meta_parts = meta.second->get_parts ();

      /**
       * First of all we need to remove Index entries for Emails
       * This is done by sending one packet and we need data about DA
       * of all Emailpackets.
       * 
       * In the event of an interruption, we will either delete these
       * Index entries already or have the option to delete them in the future.
       * 
       * If we remove the Email packats right away,
       * then we will not have access to DA to remove Index entries.
       * 
       * This will highload our requests to DHT.
       */
      IndexDeleteRequestPacket delete_index_packet;

      for (auto meta_part : (*meta_parts))
        {
          IndexDeleteRequestPacket::item delete_item;
          memcpy (&delete_item.key, meta_part.second.key, 32);
          memcpy (delete_item.da, meta_part.second.DA, 32);
          delete_index_packet.data.push_back (delete_item);
        }

      memcpy (&delete_index_packet.dht_key, meta.second->dht ().data (), 32);
      delete_index_packet.count = delete_index_packet.data.size ();
      LogPrint (eLogInfo, "EmailWorker: remove_from_dht: Cleanup I ",
                meta.second->dht ().ToBase64 ());

      std::vector<std::string> responses;
      responses = DHT_worker.deleteIndexEntries (meta.second->dht (),
                                                 delete_index_packet);

      if (responses.empty ())
        {
          LogPrint (eLogInfo, "EmailWorker: remove_from_dht: I not cleaned, key:",
                    meta.second->dht ().ToBase64 ());
        }

      /*
       * Now we can remove emails
       */
      for (auto meta_part : (*meta_parts))
        {
          EmailDeleteRequestPacket delete_email_packet;

          memcpy (delete_email_packet.DA, meta_part.second.DA, 32);
          memcpy (delete_email_packet.key, meta_part.second.key, 32);

          i2p::data::Tag<32> email_dht_key (meta_part.second.key);
          //i2p::data::Tag<32> email_del_auth (meta_part.second.DA);
          LogPrint (eLogInfo, "EmailWorker: remove_from_dht: Removing E ",
                    email_dht_key.ToBase64 ());

          /// We need to remove packets for all received email from nodes
          std::vector<std::string> responses;
          responses = DHT_worker.deleteEmail (email_dht_key,
                                              DataE, delete_email_packet);

          if (responses.empty ())
            {
              LogPrint (eLogInfo,
                        "EmailWorker: remove_from_dht: E not removed from DHT, key: ",
                        email_dht_key.ToBase64 ());
            }
        }

      
    }
  LogPrint (eLogInfo, "EmailWorker: remove_from_dht: Finished");
}

bool
EmailWorker::check_thread_exist (const std::string &identity_name)
{
  auto it = m_check_threads.find (identity_name);
  if (it != m_check_threads.end ())
    return true;

  return false;
}

} // namespace bote
