/**
 * Copyright (C) 2019-2022 polistern
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

#define SEND_EMAIL_INTERVAL (5 * 60)
#define CHECK_EMAIL_INTERVAL (5 * 60)

using sp_id_full = std::shared_ptr<pbote::BoteIdentityFull>;
using thread_map
    = std::unordered_map<std::string, std::shared_ptr<std::thread> >;

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

  std::vector<std::shared_ptr<pbote::Email> > check_inbox ();

private:
  void run ();

  void checkEmailTask (const sp_id_full &identity);
  void incompleteEmailTask ();
  void sendEmailTask ();

  std::vector<pbote::IndexPacket> retrieveIndex (const sp_id_full &identity);
  std::vector<pbote::EmailEncryptedPacket>
  retrieveEmailPacket (const std::vector<pbote::IndexPacket> &index_packets);

  static std::vector<pbote::EmailUnencryptedPacket>
  loadLocalIncompletePacket ();

  static std::vector<std::shared_ptr<pbote::Email> > checkOutbox ();

  std::vector<pbote::Email>
  processEmail (const sp_id_full &identity,
                const std::vector<pbote::EmailEncryptedPacket> &mail_packets);

  bool check_thread_exist (const std::string &identity_name);

  bool started_;
  std::thread *m_send_thread_;
  std::thread *m_worker_thread_;
  thread_map m_check_threads_;
};

extern EmailWorker email_worker;

} // namespace kademlia
} // namespace pbote

#endif // PBOTED_SRC_EMAIL_WORKER_H_
