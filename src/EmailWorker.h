/**
 * Copyright (C) 2019-2022, polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef PBOTED_SRC_EMAIL_WORKER_H_
#define PBOTED_SRC_EMAIL_WORKER_H_

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <thread>

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

using sp_id_full = std::shared_ptr<BoteIdentityFull>;
using thread_map
    = std::unordered_map<std::string, std::shared_ptr<std::thread> >;
using v_sp_email = std::vector<std::shared_ptr<Email> >;
using v_sp_email_meta
    = std::vector<std::shared_ptr<EmailMetadata> >;
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

  void checkEmailTask (const sp_id_full &identity);
  void incompleteEmailTask ();
  void sendEmailTask ();
  void check_delivery_task ();

  std::vector<IndexPacket> retrieveIndex (const sp_id_full &identity);
  std::vector<EmailEncryptedPacket>
  retrieveEmail (const std::vector<IndexPacket> &indices);

  static void check_outbox (v_sp_email &emails);
  static void check_sentbox (v_sp_email_meta &metas);
  static map_sp_email_meta get_incomplete ();

  void processEmail (const sp_id_full &identity,
                     const std::vector<EmailEncryptedPacket> &mail_packets);

  bool check_thread_exist (const std::string &identity_name);

  bool started_;
  std::thread *m_worker_thread_;
  std::thread *m_send_thread_;
  std::thread *m_delivery_thread_;
  std::thread *m_incomplete_thread_;
  thread_map m_check_threads_;
};

extern EmailWorker email_worker;

} // namespace kademlia
} // namespace pbote

#endif // PBOTED_SRC_EMAIL_WORKER_H_
