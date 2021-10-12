/**
 * Copyright (c) 2019-2021 polistern
 */

#ifndef PBOTE_EMAILWORKER_H__
#define PBOTE_EMAILWORKER_H__


#include <algorithm>
#include <memory>
#include <thread>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include "lib/lzma/LzmaDec.h"
#include "lib/lzma/LzmaEnc.h"
#include "lib/lzma/7zTypes.h"

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

  void startCheckEmailTask();
  bool stopCheckEmailTask();
  void startIncompleteEmailTask();
  bool stopIncompleteEmailTask();
  void startSendEmailTask();
  bool stopSendEmailTask();

  static pbote::IndexPacket parseIndexPkt(const std::vector<uint8_t>& buf, bool from_net);
  static pbote::EmailEncryptedPacket parseEmailEncryptedPkt(uint8_t * buf, size_t len, bool from_net);

  std::vector<uint8_t> decryptData(uint8_t* enc, size_t elen);
  std::vector<uint8_t> encryptData(uint8_t* data, size_t dlen, const pbote::EmailIdentityPublic& recipient);

 private:
  void run();

  void checkEmailTask();
  void incompleteEmailTask();
  void sendEmailTask();

  std::vector<pbote::IndexPacket> retrieveIndex(const std::shared_ptr<pbote::EmailIdentityFull>& identity);
  std::vector<pbote::EmailEncryptedPacket> retrieveEmailPacket(const std::vector<pbote::IndexPacket>& index_packets);

  static std::vector<pbote::EmailUnencryptedPacket> loadLocalIncompletePacket();

  static std::vector<std::shared_ptr<pbote::Email>> checkOutbox();

  std::vector<pbote::Email> processEmail(const std::vector<pbote::EmailEncryptedPacket>& mail_packets);

  static bool saveEmailInboxPacket(pbote::Email mail);

  bool started_;
  std::thread *m_check_email_thread_;
  std::thread *m_send_email_thread_;
  std::thread *m_worker_thread_;

  std::vector<std::shared_ptr<pbote::EmailIdentityFull>> email_identities;
};

extern EmailWorker email_worker;

} // kademlia
} // pbote

#endif // PBOTE_EMAILWORKER_H__
