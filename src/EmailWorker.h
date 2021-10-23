/**
 * Copyright (c) 2019-2021 polistern
 */

#ifndef PBOTE_EMAILWORKER_H__
#define PBOTE_EMAILWORKER_H__

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <thread>

#include "Email.h"

namespace pbote {
namespace kademlia {

const int SEND_EMAIL_INTERVAL = 5 * 60;
const int CHECK_EMAIL_INTERVAL = 5 * 60;

class EmailWorker {
public:
  EmailWorker();
  ~EmailWorker();

  void start();
  void stop();

  void startCheckEmailTasks();
  bool stopCheckEmailTasks();
  void startIncompleteEmailTask();
  bool stopIncompleteEmailTask();
  void startSendEmailTask();
  bool stopSendEmailTask();

  std::vector<std::shared_ptr<pbote::Email>> check_inbox();

  std::vector<uint8_t>
  decryptData(const std::shared_ptr<pbote::EmailIdentityFull> &identity,
              uint8_t *enc, size_t elen);
  std::vector<uint8_t>
  encryptData(const std::shared_ptr<pbote::EmailIdentityFull> &identity,
              uint8_t *data, size_t dlen,
              const pbote::EmailIdentityPublic &recipient);

private:
  void run();

  void
  checkEmailTask(const std::shared_ptr<pbote::EmailIdentityFull> &identity);
  void incompleteEmailTask();
  void sendEmailTask();

  std::vector<pbote::IndexPacket>
  retrieveIndex(const std::shared_ptr<pbote::EmailIdentityFull> &identity);
  std::vector<pbote::EmailEncryptedPacket>
  retrieveEmailPacket(const std::vector<pbote::IndexPacket> &index_packets);

  static std::vector<pbote::EmailUnencryptedPacket> loadLocalIncompletePacket();

  static std::vector<std::shared_ptr<pbote::Email>> checkOutbox();

  std::vector<pbote::Email>
  processEmail(const std::shared_ptr<pbote::EmailIdentityFull> &identity,
               const std::vector<pbote::EmailEncryptedPacket> &mail_packets);

  bool started_;
  std::vector<std::shared_ptr<std::thread>> m_check_email_threads_;
  std::thread *m_send_email_thread_;
  std::thread *m_worker_thread_;

  std::vector<std::shared_ptr<pbote::EmailIdentityFull>> email_identities;
};

extern EmailWorker email_worker;

} // namespace kademlia
} // namespace pbote

#endif // PBOTE_EMAILWORKER_H__
