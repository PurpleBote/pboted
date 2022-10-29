/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#pragma once
#ifndef PBOTED_SRC_EMAIL_WORKER_H
#define PBOTED_SRC_EMAIL_WORKER_H

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <thread>
#include <unordered_map>

#include "Email.h"

namespace pbote
{
namespace kademlia
{

#ifdef NDEBUG
#define SEND_EMAIL_INTERVAL (5 * 60)
#else
#define SEND_EMAIL_INTERVAL (1 * 60)
#endif // NDEBUG

#define CHECK_EMAIL_INTERVAL (5 * 60)

#define DELIVERY_EMAIL_INTERVAL (5 * 60)

#define FIRST_RUN_WAITING 30

using sp_id_full = std::shared_ptr<BoteIdentityFull>;
using thread_map
    = std::unordered_map<std::string, std::shared_ptr<std::thread> >;
using v_index = std::vector<IndexPacket>;
using v_enc_email = std::vector<EmailEncryptedPacket>;
using v_sp_email = std::vector<std::shared_ptr<Email> >;
using v_sp_email_meta = std::vector<std::shared_ptr<EmailMetadata> >;
using map_sp_email_meta
    = std::map<i2p::data::Tag<32>, std::shared_ptr<EmailMetadata> >;

class EmailWorker
{
public:
  EmailWorker ();
  ~EmailWorker ();

  void start ();
  void stop ();

  void startCheckEmailTasks ();
  bool stopCheckEmailTasks ();

  void startIncompleteEmailTask ();
  bool stopIncompleteEmailTask ();

  void startSendEmailTask ();
  bool stopSendEmailTask ();

  void start_check_delivery_task ();
  bool stop_check_delivery_task ();

  v_sp_email check_inbox ();

private:
  void run ();

  void check_email_task (const sp_id_full &identity);
  void incomplete_email_task ();
  void send_email_task ();
  void check_delivery_task ();

  v_index retrieve_index (const sp_id_full &identity);
  v_enc_email retrieve_email (const v_index &indices);

  static void check_outbox (v_sp_email &emails);
  static void check_sentbox (v_sp_email_meta &metas);
  static map_sp_email_meta get_incomplete ();

  void process_emails (const sp_id_full &identity,
                       const v_enc_email &mail_packets);

  bool check_thread_exist (const std::string &identity_name);

  bool m_main_started;

  std::thread *m_worker_thread;
  std::thread *m_send_thread;
  std::thread *m_delivery_thread;
  std::thread *m_incomplete_thread;
  thread_map m_check_threads;

  mutable std::mutex m_check_mutex,
                     m_incomplete_mutex,
                     m_send_mutex,
                     m_delivery_mutex;
  std::condition_variable m_check_cv;
};

extern EmailWorker email_worker;

} // namespace kademlia
} // namespace pbote

#endif // PBOTED_SRC_EMAIL_WORKER_H
